package utils

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"strings"
	"time"
)

const (
	contentTypeMultipartMixed       = "multipart/mixed"
	contentTypeMultipartAlternative = "multipart/alternative"
	contentTypeMultipartRelated     = "multipart/related"
	contentTypeTextHtml             = "text/html"
	contentTypeTextPlain            = "text/plain"
	contentTypeOctetStream          = "application/octet-stream"
)

func Parse(r io.Reader) (email Email, err error) {
	rawData, err := io.ReadAll(r)
	if err != nil {
		fmt.Printf("Error reading raw email: %v\n", err)
		return email, err
	}
	if err := os.WriteFile("/tmp/raw_email.txt", rawData, 0644); err != nil {
		fmt.Printf("Error saving raw email: %v\n", err)
	}
	r = bytes.NewReader(rawData)

	msg, err := mail.ReadMessage(r)
	if err != nil {
		fmt.Printf("Error reading message: %v\n", err)
		return email, err
	}

	email, err = createEmailFromHeader(msg.Header)
	if err != nil {
		fmt.Printf("Error creating email from header: %v\n", err)
		return email, err
	}

	email.ContentType = msg.Header.Get("Content-Type")
	fmt.Println("Content-Type:", email.ContentType)
	if email.ContentType == "" {
		fmt.Println("Warning: Content-Type header is empty")
	}

	contentType, params, err := parseContentType(email.ContentType)
	if err != nil {
		fmt.Printf("Error parsing Content-Type '%s': %v\n", email.ContentType, err)
		return email, err
	}
	fmt.Printf("Parsed Content-Type: %s, Params: %v\n", contentType, params)

	switch contentType {
	case contentTypeMultipartMixed:
		fmt.Println("Processing multipart/mixed")
		email.TextBody, email.HTMLBody, email.Attachments, email.EmbeddedFiles, err = parseMultipartMixed(msg.Body, params["boundary"])
	case contentTypeMultipartAlternative:
		fmt.Println("Processing multipart/alternative")
		email.TextBody, email.HTMLBody, email.EmbeddedFiles, err = parseMultipartAlternative(msg.Body, params["boundary"])
	case contentTypeMultipartRelated:
		fmt.Println("Processing multipart/related")
		email.TextBody, email.HTMLBody, email.EmbeddedFiles, err = parseMultipartRelated(msg.Body, params["boundary"])
	case contentTypeTextPlain:
		fmt.Println("Processing text/plain")
		message, _ := io.ReadAll(msg.Body)
		email.TextBody = strings.TrimSuffix(string(message[:]), "\n")
	case contentTypeTextHtml:
		fmt.Println("Processing text/html")
		message, _ := io.ReadAll(msg.Body)
		email.HTMLBody = strings.TrimSuffix(string(message[:]), "\n")
	default:
		fmt.Printf("Processing default content type: %s\n", contentType)
		email.Content, err = decodeContent(msg.Body, msg.Header.Get("Content-Transfer-Encoding"))
	}
	if err != nil {
		fmt.Printf("Error processing content: %v\n", err)
	}

	return email, err
}

// parseMultipartMixed modified to handle application/octet-stream explicitly
func parseMultipartMixed(msg io.Reader, boundary string) (textBody, htmlBody string, attachments []Attachment, embeddedFiles []EmbeddedFile, err error) {
	mr := multipart.NewReader(msg, boundary)
	for i := 0; ; i++ {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Printf("Error reading multipart/mixed part %d: %v\n", i, err)
			return textBody, htmlBody, attachments, embeddedFiles, err
		}

		contentType, params, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			fmt.Printf("Error parsing Content-Type for part %d: %v\n", i, err)
			return textBody, htmlBody, attachments, embeddedFiles, err
		}
		fmt.Printf("Part %d Content-Type: %s, Params: %v\n", i, contentType, params)

		switch contentType {
		case contentTypeMultipartAlternative:
			fmt.Printf("Processing multipart/alternative in part %d\n", i)
			textBody, htmlBody, embeddedFiles, err = parseMultipartAlternative(part, params["boundary"])
			if err != nil {
				fmt.Printf("Error processing multipart/alternative part %d: %v\n", i, err)
				return textBody, htmlBody, attachments, embeddedFiles, err
			}
		case contentTypeMultipartRelated:
			fmt.Printf("Processing multipart/related in part %d\n", i)
			textBody, htmlBody, embeddedFiles, err = parseMultipartRelated(part, params["boundary"])
			if err != nil {
				fmt.Printf("Error processing multipart/related part %d: %v\n", i, err)
				return textBody, htmlBody, attachments, embeddedFiles, err
			}
		case contentTypeTextPlain:
			fmt.Printf("Processing text/plain in part %d\n", i)
			ppContent, err := io.ReadAll(part)
			if err != nil {
				fmt.Printf("Error reading text/plain part %d: %v\n", i, err)
				return textBody, htmlBody, attachments, embeddedFiles, err
			}
			textBody += strings.TrimSuffix(string(ppContent[:]), "\n")
		case contentTypeTextHtml:
			fmt.Printf("Processing text/html in part %d\n", i)
			ppContent, err := io.ReadAll(part)
			if err != nil {
				fmt.Printf("Error reading text/html part %d: %v\n", i, err)
				return textBody, htmlBody, attachments, embeddedFiles, err
			}
			htmlBody += strings.TrimSuffix(string(ppContent[:]), "\n")
		case contentTypeOctetStream:
			fmt.Printf("Processing application/octet-stream in part %d\n", i)
			if isAttachment(part) {
				at, err := decodeAttachment(part)
				if err != nil {
					fmt.Printf("Error decoding attachment part %d: %v\n", i, err)
					return textBody, htmlBody, attachments, embeddedFiles, err
				}
				fmt.Printf("Decoded attachment: %s (Content-Type: %s)\n", at.Filename, at.ContentType)
				attachments = append(attachments, at)
			} else {
				fmt.Printf("Part %d is not an attachment but has content type %s\n", i, contentType)
				return textBody, htmlBody, attachments, embeddedFiles, fmt.Errorf("part %d with content type %s is not an attachment", i, contentType)
			}
		default:
			fmt.Printf("Checking if part %d is an attachment (Content-Type: %s)\n", i, contentType)
			if isAttachment(part) {
				at, err := decodeAttachment(part)
				if err != nil {
					fmt.Printf("Error decoding attachment part %d: %v\n", i, err)
					return textBody, htmlBody, attachments, embeddedFiles, err
				}
				fmt.Printf("Decoded attachment: %s (Content-Type: %s)\n", at.Filename, at.ContentType)
				attachments = append(attachments, at)
			} else {
				fmt.Printf("Unknown multipart/mixed nested mime type for part %d: %s\n", i, contentType)
				return textBody, htmlBody, attachments, embeddedFiles, fmt.Errorf("unknown multipart/mixed nested mime type: %s", contentType)
			}
		}
	}
	fmt.Printf("Finished processing multipart/mixed: %d attachments found\n", len(attachments))
	return textBody, htmlBody, attachments, embeddedFiles, nil
}

func isAttachment(part *multipart.Part) bool {
	return part.FileName() != ""
}

func parseContentType(contentTypeHeader string) (contentType string, params map[string]string, err error) {
	if contentTypeHeader == "" {
		contentType = contentTypeTextPlain
		return
	}

	return mime.ParseMediaType(contentTypeHeader)
}

func parseMultipartRelated(msg io.Reader, boundary string) (textBody, htmlBody string, embeddedFiles []EmbeddedFile, err error) {
	pmr := multipart.NewReader(msg, boundary)
	for {
		part, err := pmr.NextPart()

		if err == io.EOF {
			break
		} else if err != nil {
			return textBody, htmlBody, embeddedFiles, err
		}

		contentType, params, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			return textBody, htmlBody, embeddedFiles, err
		}

		switch contentType {
		case contentTypeTextPlain:
			ppContent, err := io.ReadAll(part)
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			textBody += strings.TrimSuffix(string(ppContent[:]), "\n")
		case contentTypeTextHtml:
			ppContent, err := io.ReadAll(part)
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			htmlBody += strings.TrimSuffix(string(ppContent[:]), "\n")
		case contentTypeMultipartAlternative:
			tb, hb, ef, err := parseMultipartAlternative(part, params["boundary"])
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			htmlBody += hb
			textBody += tb
			embeddedFiles = append(embeddedFiles, ef...)
		default:
			if isEmbeddedFile(part) {
				ef, err := decodeEmbeddedFile(part)
				if err != nil {
					return textBody, htmlBody, embeddedFiles, err
				}

				embeddedFiles = append(embeddedFiles, ef)
			} else {
				return textBody, htmlBody, embeddedFiles, fmt.Errorf("Can't process multipart/related inner mime type: %s", contentType)
			}
		}
	}

	return textBody, htmlBody, embeddedFiles, err
}

func parseMultipartAlternative(msg io.Reader, boundary string) (textBody, htmlBody string, embeddedFiles []EmbeddedFile, err error) {
	pmr := multipart.NewReader(msg, boundary)
	for {
		part, err := pmr.NextPart()

		if err == io.EOF {
			break
		} else if err != nil {
			return textBody, htmlBody, embeddedFiles, err
		}

		contentType, params, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			return textBody, htmlBody, embeddedFiles, err
		}

		switch contentType {
		case contentTypeTextPlain:
			ppContent, err := io.ReadAll(part)
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			textBody += strings.TrimSuffix(string(ppContent[:]), "\n")
		case contentTypeTextHtml:
			ppContent, err := io.ReadAll(part)
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			htmlBody += strings.TrimSuffix(string(ppContent[:]), "\n")
		case contentTypeMultipartRelated:
			tb, hb, ef, err := parseMultipartRelated(part, params["boundary"])
			if err != nil {
				return textBody, htmlBody, embeddedFiles, err
			}

			htmlBody += hb
			textBody += tb
			embeddedFiles = append(embeddedFiles, ef...)
		default:
			if isEmbeddedFile(part) {
				ef, err := decodeEmbeddedFile(part)
				if err != nil {
					return textBody, htmlBody, embeddedFiles, err
				}

				embeddedFiles = append(embeddedFiles, ef)
			} else {
				return textBody, htmlBody, embeddedFiles, fmt.Errorf("Can't process multipart/alternative inner mime type: %s", contentType)
			}
		}
	}

	return textBody, htmlBody, embeddedFiles, err
}

func isEmbeddedFile(part *multipart.Part) bool {
	return part.Header.Get("Content-Transfer-Encoding") != ""
}

func decodeEmbeddedFile(part *multipart.Part) (ef EmbeddedFile, err error) {
	cid := decodeMimeSentence(part.Header.Get("Content-Id"))
	decoded, err := decodeContent(part, part.Header.Get("Content-Transfer-Encoding"))
	if err != nil {
		return
	}

	ef.CID = strings.Trim(cid, "<>")
	ef.Data = decoded
	ef.ContentType = part.Header.Get("Content-Type")

	return
}

func decodeAttachment(part *multipart.Part) (at Attachment, err error) {
	filename := decodeMimeSentence(part.FileName())
	if filename == "" {
		filename = "unnamed_attachment"
	}
	fmt.Printf("Decoding attachment: %s (Content-Transfer-Encoding: %s)\n", filename, part.Header.Get("Content-Transfer-Encoding"))

	decoded, err := decodeContent(part, part.Header.Get("Content-Transfer-Encoding"))
	if err != nil {
		fmt.Printf("Error decoding content for attachment %s: %v\n", filename, err)
		return at, err
	}

	at.Filename = filename
	at.Data = decoded
	contentType, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
	if contentType == "" {
		contentType = contentTypeOctetStream
	}
	at.ContentType = contentType

	if data, err := io.ReadAll(decoded); err == nil {
		fmt.Printf("Attachment %s decoded data size: %d bytes\n", filename, len(data))
		at.Data = bytes.NewReader(data)
	} else {
		fmt.Printf("Error reading decoded attachment data: %v\n", err)
		return at, err
	}

	return at, nil
}

func decodeContent(content io.Reader, encoding string) (io.Reader, error) {
	switch strings.ToLower(encoding) {
	case "base64":
		decoded := base64.NewDecoder(base64.StdEncoding, content)
		b, err := io.ReadAll(decoded)
		if err != nil {
			return nil, fmt.Errorf("base64 decoding failed: %v", err)
		}
		if len(b) == 0 {
			return nil, fmt.Errorf("base64 decoding resulted in empty data")
		}
		return bytes.NewReader(b), nil
	case "7bit", "8bit", "":
		dd, err := io.ReadAll(content)
		if err != nil {
			return nil, fmt.Errorf("reading %s content failed: %v", encoding, err)
		}
		return bytes.NewReader(dd), nil
	default:
		return nil, fmt.Errorf("unsupported encoding: %s", encoding)
	}
}

func createEmailFromHeader(header mail.Header) (email Email, err error) {
	hp := headerParser{header: &header}

	email.Subject = decodeMimeSentence(header.Get("Subject"))
	email.From = hp.parseAddressList(header.Get("From"))
	email.Sender = hp.parseAddress(header.Get("Sender"))
	email.ReplyTo = hp.parseAddressList(header.Get("Reply-To"))
	email.To = hp.parseAddressList(header.Get("To"))
	email.Cc = hp.parseAddressList(header.Get("Cc"))
	email.Bcc = hp.parseAddressList(header.Get("Bcc"))
	email.Date = hp.parseTime(header.Get("Date"))
	email.ResentFrom = hp.parseAddressList(header.Get("Resent-From"))
	email.ResentSender = hp.parseAddress(header.Get("Resent-Sender"))
	email.ResentTo = hp.parseAddressList(header.Get("Resent-To"))
	email.ResentCc = hp.parseAddressList(header.Get("Resent-Cc"))
	email.ResentBcc = hp.parseAddressList(header.Get("Resent-Bcc"))
	email.ResentMessageID = hp.parseMessageId(header.Get("Resent-Message-ID"))
	email.MessageID = hp.parseMessageId(header.Get("Message-ID"))
	email.InReplyTo = hp.parseMessageIdList(header.Get("In-Reply-To"))
	email.References = hp.parseMessageIdList(header.Get("References"))
	email.ResentDate = hp.parseTime(header.Get("Resent-Date"))

	if hp.err != nil {
		err = hp.err
		return
	}

	email.Header, err = decodeHeaderMime(header)
	if err != nil {
		return
	}

	return
}
func decodeHeaderMime(header mail.Header) (mail.Header, error) {
	parsedHeader := map[string][]string{}

	for headerName, headerData := range header {

		parsedHeaderData := []string{}
		for _, headerValue := range headerData {
			parsedHeaderData = append(parsedHeaderData, decodeMimeSentence(headerValue))
		}

		parsedHeader[headerName] = parsedHeaderData
	}

	return mail.Header(parsedHeader), nil
}

func decodeMimeSentence(s string) string {
	result := []string{}
	ss := strings.Split(s, " ")

	for _, word := range ss {
		dec := new(mime.WordDecoder)
		w, err := dec.Decode(word)
		if err != nil {
			if len(result) == 0 {
				w = word
			} else {
				w = " " + word
			}
		}

		result = append(result, w)
	}

	return strings.Join(result, "")
}

type headerParser struct {
	header *mail.Header
	err    error
}

func (hp headerParser) parseAddress(s string) (ma *mail.Address) {
	if hp.err != nil {
		return nil
	}

	if strings.Trim(s, " \n") != "" {
		ma, hp.err = mail.ParseAddress(s)

		return ma
	}

	return nil
}

func (hp headerParser) parseAddressList(s string) (ma []*mail.Address) {
	if hp.err != nil {
		return
	}

	if strings.Trim(s, " \n") != "" {
		ma, hp.err = mail.ParseAddressList(s)
		return
	}

	return
}

func (hp headerParser) parseTime(s string) (t time.Time) {
	if hp.err != nil || s == "" {
		return
	}

	formats := []string{
		time.RFC1123Z,
		"Mon, 2 Jan 2006 15:04:05 -0700",
		time.RFC1123Z + " (MST)",
		"Mon, 2 Jan 2006 15:04:05 -0700 (MST)",
	}

	for _, format := range formats {
		t, hp.err = time.Parse(format, s)
		if hp.err == nil {
			return
		}
	}

	return
}

func (hp headerParser) parseMessageId(s string) string {
	if hp.err != nil {
		return ""
	}

	return strings.Trim(s, "<> ")
}

func (hp headerParser) parseMessageIdList(s string) (result []string) {
	if hp.err != nil {
		return
	}

	for _, p := range strings.Split(s, " ") {
		if strings.Trim(p, " \n") != "" {
			result = append(result, hp.parseMessageId(p))
		}
	}

	return
}

// Ensure the Attachment, EmbeddedFile, and Email structs remain as provided
type Attachment struct {
	Filename    string
	ContentType string
	Data        io.Reader
}

type EmbeddedFile struct {
	CID         string
	ContentType string
	Data        io.Reader
}

type Email struct {
	Header mail.Header

	Subject    string
	Sender     *mail.Address
	From       []*mail.Address
	ReplyTo    []*mail.Address
	To         []*mail.Address
	Cc         []*mail.Address
	Bcc        []*mail.Address
	Date       time.Time
	MessageID  string
	InReplyTo  []string
	References []string

	ResentFrom      []*mail.Address
	ResentSender    *mail.Address
	ResentTo        []*mail.Address
	ResentDate      time.Time
	ResentCc        []*mail.Address
	ResentBcc       []*mail.Address
	ResentMessageID string

	ContentType string
	Content     io.Reader

	HTMLBody string
	TextBody string

	Attachments   []Attachment
	EmbeddedFiles []EmbeddedFile
}
