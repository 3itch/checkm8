package uswid

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"io/ioutil"

	"github.com/fxamacker/cbor/v2"
	"github.com/CodingVoid/swid"
	"github.com/google/uuid"
)

var magic []byte = []byte{0x53, 0x42, 0x4F, 0x4D, 0xD6, 0xBA, 0x2E, 0xAC, 0xA3, 0xE6, 0x7A, 0x52, 0xAA, 0xEE, 0x3B, 0xAF} // can't be const...
const flagCompressZlib = 0x01

// uSWID is essentially supposed to be a collection of CoSWID/SWID tags.
type UswidSoftwareIdentity struct {
	Identities []swid.SoftwareIdentity
}

// strip comments from JSON to get pure JSON. optionally remove whitespaces, tabs and newlines
func jsonMinify(json string, stripSpace bool) string {
	var out strings.Builder
	indexMultilineComment := -1
	indexInlineComment := -1
	inJsonStr := false
	skip := false
	for i, r := range json {
		if skip {
			skip = false
			continue
		}
		switch r {
		case '/':
			if !inJsonStr && indexMultilineComment == -1 && indexInlineComment == -1 {
				// if currently not in a comment or json string, a slash
				// could be the beginning of a new comment. look ahead and see
				if len(json) > i+1 {
					if json[i+1] == '/' {
						indexInlineComment = i
						// since we already looked ahead, we don't need
						// to consider the next character
						skip = true
					} else if json[i+1] == '*' {
						indexMultilineComment = i
						// since we already looked ahead, we don't need
						// to consider the next character
						skip = true
					}
				}
			}
		case '*':
			if indexMultilineComment != -1 {
				// we are currently in a multiline comment. A star sign could mean
				// the end of our multiline comment. look ahead and see
				if len(json) > i+1 {
					if json[i+1] == '/' {
						indexMultilineComment = -1
						// since we already looked ahead, we don't need to consider
						// the next character
						skip = true
						// a bit nasty but since we don't want to print the current
						// character, we need to skip the rest
						continue
					}
				}
			}
		case '"':
			if inJsonStr {
				inJsonStr = false
			} else if !inJsonStr && indexMultilineComment == -1 && indexInlineComment == -1 {
				// if we are currently not in a comment, a quote sign can only mean
				// we got into a JSON string
				inJsonStr = true
			}
		case '\\':
			if len(json) > i+1 {
				if json[i+1] == '"' {
					// next quote sign is escaped and therefore looses it's meaning
					// as start/end of JSON string. put into output and skip both
					out.WriteRune('\\')
					out.WriteRune('"')
					skip = true
					continue
				} else if json[i+1] == '\\' {
					// the next escape must loose it's power to escape stuff
					// because it itself is escaped
					out.WriteRune('\\')
					skip = true
				}
			}
		case '\n':
			indexInlineComment = -1
		case '\r':
			indexInlineComment = -1
		}
		if indexMultilineComment == -1 && indexInlineComment == -1 {
			// only consider in output if character is outside of any comment
			if !stripSpace || inJsonStr || (r != '\n' && r != '\r' && r != '\t' && r != ' ') {
				// everything considered a whitespace (line feed, carriage return, tab, whitespace)
				// is only candidate for output if desired
				out.WriteRune(r)
			}
		}
	}
	return out.String()
}

func (uswid *UswidSoftwareIdentity) FromFile(filepath string) error {
	inputFile, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}

	/* check file extension of input file */
	ifParts := strings.Split(filepath, ".")
	switch ifParts[len(ifParts)-1] {
	case "pc":
		pcStr := strings.ReplaceAll(string(inputFile), "\r\n", "\n") // replace windows line endings with line feeds
		err = uswid.FromPC(pcStr, filepath)
	case "json":
		jsonStr := jsonMinify(string(inputFile), false)
		err = uswid.FromJSON(jsonStr)
	case "xml":
		err = uswid.FromXML(string(inputFile))
	case "cbor":
		err = uswid.FromCBOR(inputFile, false)
	case "uswid":
		fallthrough
	default:
		_, err = uswid.FromUSWID(inputFile)
	}
	if err != nil {
		return fmt.Errorf("parsing %s: %w", filepath, err)
	}
	return nil
}

func (uswid *UswidSoftwareIdentity) FromCBOR(blob []byte, compressed bool) error {
	buf := bytes.NewBuffer(blob)
	var decoder *cbor.Decoder
	if compressed {
		rd, err := zlib.NewReader(buf)
		if err != nil {
			return fmt.Errorf("create zlib reader: %w", err)
		}
		decoder = cbor.NewDecoder(rd)
	} else {
		decoder = cbor.NewDecoder(buf)
	}
	for {
		var id swid.SoftwareIdentity
		err := decoder.Decode(&id)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("decoding cbor: %w", err)
		}
		uswid.Identities = append(uswid.Identities, id)
	}
	return nil
}

// returns the offset where the uswid data was found (first byte) in blob
func (uswid *UswidSoftwareIdentity) FromUSWID(blob []byte) (int, error) {
	var err error
	offset := bytes.Index(blob, magic)
	if offset == -1 {
		return -1, errors.New("could not find uswid data")
	}
	headerVersion := blob[offset+16]
	if headerVersion != 2 {
		return offset, errors.New("no known header version")
	}
	//header_len := binary.LittleEndian.Uint16(blob[offset+17:offset+19])
	payloadLen := binary.LittleEndian.Uint32(blob[offset+19 : offset+23])
	flags := blob[offset+23]
	if (flags & flagCompressZlib) != 0 {
		err = uswid.FromCBOR(blob[offset+24:uint32(offset)+24+payloadLen], true)
	} else {
		err = uswid.FromCBOR(blob[offset+24:uint32(offset)+24+payloadLen], false)
	}
	if err != nil {
		return -1, fmt.Errorf("extract CBOR: %w", err)
	}
	return offset, nil
}

func (uswid *UswidSoftwareIdentity) FromJSON(jsonStr string) error {
	if len(jsonStr) == 0 {
		return errors.New("input data empty")
	}

	jsonStr = strings.TrimSpace(jsonStr)

	if jsonStr[0] == '[' && jsonStr[len(jsonStr)-1] == ']' {
		var uswidID UswidSoftwareIdentity
		if err := json.Unmarshal([]byte(jsonStr), &uswidID.Identities); err != nil {
			return err
		}
		uswid.Identities = append(uswid.Identities, uswidID.Identities...)
	} else {
		var id swid.SoftwareIdentity
		if err := id.FromJSON([]byte(jsonStr)); err != nil {
			return err
		}
		uswid.Identities = append(uswid.Identities, id)
	}
	return nil
}

func (uswid *UswidSoftwareIdentity) FromXML(xmlStr string) error {
	if len(xmlStr) == 0 {
		return errors.New("input data empty")
	}

	var offset int64 = 0
	for offset < int64(len(xmlStr)) {
		var id swid.SoftwareIdentity
		xmlDecoder := xml.NewDecoder(bytes.NewReader([]byte(xmlStr[offset:])))
		if err := xmlDecoder.Decode(&id); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		uswid.Identities = append(uswid.Identities, id)
		offset += xmlDecoder.InputOffset()
	}
	return nil
}

func (uswid *UswidSoftwareIdentity) FromPC(pcData string, filename string) error {
	pcLines := strings.Split(pcData, "\n")
	var id swid.SoftwareIdentity
	var softwareMeta swid.SoftwareMeta
	for _, pcLine := range pcLines {
		field := strings.Split(pcLine, ":")
		if (len(field) != 2) {
			continue
		}
		value := strings.TrimSpace(field[1])
		switch field[0] {
		case "Name":
			id.SoftwareName = value
		case "Description":
			softwareMeta.Summary = value
		case "Version":
			id.SoftwareVersion = value
		}
	}
	id.AddSoftwareMeta(softwareMeta)
	id.TagID = *swid.NewTagID(uuid.NewSHA1(uuid.NameSpaceDNS, []byte(filename)))
	if len(id.Entities) == 0 {
		entity, _ := swid.NewEntity("goswid (auto-generated)", swid.RoleTagCreator)
		id.AddEntity(*entity)
	}
	uswid.Identities = append(uswid.Identities, id)
	return nil
}

func (uswid UswidSoftwareIdentity) ToUSWID(compress bool) ([]byte, error) {
	var header [16 + 1 + 2 + 4 + 1]byte
	copy(header[:16], magic)                         // magic USWID value
	header[16] = 2                                   // header version
	binary.LittleEndian.PutUint16(header[17:19], 24) // header size

	header[23] = 0x00 // flags
	if compress {
		header[23] |= 0x01
	}
	cborBuf, err := uswid.ToCBOR(compress)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(header[19:23], uint32(len(cborBuf)))
	return append(header[:], cborBuf...), nil
}

func (uswid UswidSoftwareIdentity) ToJSON() ([]byte, error) {
	var jsonBuf []byte
	if len(uswid.Identities) > 1 {
		jsonBuf = append(jsonBuf, '[')
		jsonBuf = append(jsonBuf, ' ')
	}
	for i, id := range uswid.Identities {
		buf, err := id.ToJSON()
		if err != nil {
			return nil, fmt.Errorf("convert to JSON: %w", err)
		}
		jsonBuf = append(jsonBuf, buf...)
		if i < len(uswid.Identities)-1 {
			jsonBuf = append(jsonBuf, ',')
		}
	}
	if len(uswid.Identities) > 1 {
		jsonBuf = append(jsonBuf, ' ')
		jsonBuf = append(jsonBuf, ']')
	}
	return jsonBuf, nil
}

func (uswid UswidSoftwareIdentity) ToXML() ([]byte, error) {
	var xmlBuf []byte
	for _, id := range uswid.Identities {
		id.XMLName.Space = "http://standards.iso.org/iso/19770/-2/2015/schema.xsd"
		id.XMLName.Local = "SoftwareIdentity"

		buf, err := id.ToXML()
		if err != nil {
			return nil, fmt.Errorf("convert to XML: %w", err)
		}
		xmlBuf = append(xmlBuf, buf...)
	}
	return xmlBuf, nil
}

func (uswid UswidSoftwareIdentity) ToCBOR(compress bool) ([]byte, error) {
	var cborBuf []byte
	for _, id := range uswid.Identities {
		buf, err := id.ToCBOR()
		if err != nil {
			return nil, fmt.Errorf("convert to CBOR: %w", err)
		}
		cborBuf = append(cborBuf, buf...)
	}
	if compress {
		var buf bytes.Buffer
		zlibWriter := zlib.NewWriter(&buf)
		_, err := zlibWriter.Write(cborBuf)
		if err != nil {
			return nil, fmt.Errorf("cannot zlib compress CBOR data: %w", err)
		}
		zlibWriter.Close()
		return buf.Bytes(), nil
	} else {
		return cborBuf, nil
	}
}
