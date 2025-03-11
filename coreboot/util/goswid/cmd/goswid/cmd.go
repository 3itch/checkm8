package main

import (
	"encoding/json"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"strconv"

	"github.com/9elements/goswid/pkg/uswid"
	"github.com/CodingVoid/swid"
	"github.com/google/uuid"
)

type FileType int

var cli struct {
	Debug         bool               `help:"Enable debug mode"`

	GenerateTagID  generateTagIDCmd  `cmd help:"generates a 16 byte type-5 SHA1 RFC 4122 UUID (possible use for tag-id)"`
	Print          printCmd          `cmd help:"print swid tag to stdout (in json format)"`
	Convert        convertCmd        `cmd help:"convert between SWID/CoSWID and different file formats (json, xml, cbor, uswid)"`
	AddPayloadFile addPayloadFileCmd `cmd help:"add payload file into an existing CoSWID tag"`
	AddLicense     addLicenseCmd     `cmd help:"add license into an existing CoSWID tag"`
}

type addLicenseCmd struct {
	LicenseHref	[]string `arg required help:"link to license (e.g. SPDX license link)"`
	InputFile   string `flag required short:"i" name:"input-file" help:"Path to imput files." type:"existingfile"`
	OutputFile	string `flag required short:"o" name:"output-file" help:"output file, either .json .xml .cbor or .uswid file" type:"path"`
}

type addPayloadFileCmd struct {
	PayloadFileName	string `flag required name:"name" help:"filename that should be added to the payload portion of the CoSWID tag"`
	PayloadFileVersion string `flag optional name:"version" help:"version of the payload file"`
	InputFile   string `flag required short:"i" name:"input-file" help:"Path to imput files." type:"existingfile"`
	OutputFile	string `flag required short:"o" name:"output-file" help:"output file, either .json .xml .cbor or .uswid file" type:"path"`
}

type convertCmd struct {
	ParentTag    string   `flag optional name:"parent" help:"It is assumed that for all supplied files, the first tag of each file is a parent tag. goswid will automatically add a link (with dependency link type) between the first given uSWID/CoSWID Tag and all other parent tags" type="existingfile"`
	InputTags   []string  `flag optional short:"i" name:"input" help:"Paths to imput files (comma seperated)" type:"existingfile"`
	RequiredTags []string `flag optional name:"requires" help:"Paths to imput files (comma seperated), which should have a 'required' link to ParentTag" type:"existingfile"`
	CompilerTags []string `flag optional name:"compiler" help:"Paths to imput files (comma seperated), which should have a 'Compiler' link to ParentTag" type:"existingfile"`
	OutputFile	 string   `flag required short:"o" name:"output" help:"output file, either .json .xml .cbor .uswid file or a dash '-' for stdout" type:"path"`
	OutputFormat string   `flag optional name:"output-format" help:"file format of output file. either json, xml, cbor or uswid. if this option is ommited, format will be guessed according to the OutputFile extension"`
	ZlibCompress bool     `flag optional short:"z" name:"zlib-compress" help:"zlib (RFC 1950) compress output, only possible with .uswid file as output" type:"path"`
}

type generateTagIDCmd struct {
	UuidgenName string   `flag required short:"n" name:"name" help:"string to use for uuid generation (e.g. software name)"`
}

type printCmd struct {
	ParentTag    string   `flag optional name:"parent" help:"It is assumed that for all supplied files, the first tag of each file is a parent tag. goswid will automatically add a link (with dependency link type) between the first given uSWID/CoSWID Tag and all other parent tags" type="existingfile"`
	InputTags   []string  `flag optional short:"i" name:"input" help:"Paths to imput files (comma seperated)" type:"existingfile"`
	RequiredTags []string `flag optional name:"requires" help:"Paths to imput files (comma seperated), which should have a 'required' link to ParentTag" type:"existingfile"`
	CompilerTags []string `flag optional name:"compiler" help:"Paths to imput files (comma seperated), which should have a 'Compiler' link to ParentTag" type:"existingfile"`
	OutputFormat string   `flag optional name:"output-format" help:"format in which to pretty print the output. currently only json"`
}

func (a *addLicenseCmd) Run() error {
	var utag uswid.UswidSoftwareIdentity
	//TODO program FromFile in swid library
	err := utag.FromFile(a.InputFile)
	if err != nil {
		return err
	}
	if len(utag.Identities) != 1 {
		return fmt.Errorf("uSWID file has %d CoSWID Identities, want only 1 Identity", len(utag.Identities))
	}

	for _, license := range a.LicenseHref {
		var link *swid.Link
		if link, err = swid.NewLink(license, *swid.NewRel(swid.RelLicense)); err != nil {
			return err
		}
		utag.Identities[0].AddLink(*link)
	}

	if err := writeFile(a.OutputFile, "", false, utag); err != nil {
		return err
	}
	return nil
}

func (a *addPayloadFileCmd) Run() error {
	var utag uswid.UswidSoftwareIdentity
	//TODO program FromFile in swid library
	err := utag.FromFile(a.InputFile)
	if err != nil {
		return err
	}
	if len(utag.Identities) != 1 {
		return fmt.Errorf("uSWID file has %d CoSWID Identities, want only 1 Identity", len(utag.Identities))
	}

	var f swid.File
	//f.Key = &key
	//f.Location = location
	f.FsName = a.PayloadFileName
	//f.Root = root
	//f.Size = &size
	f.FileVersion = a.PayloadFileVersion
	//f.Hash.HashAlgID = hashAlgID
	//f.Hash.HashValue = hashValue
	if utag.Identities[0].Payload == nil {
		utag.Identities[0].Payload = swid.NewPayload()
	}
	utag.Identities[0].Payload.AddFile(f)

	if err := writeFile(a.OutputFile, "", false, utag); err != nil {
		return err
	}
	return nil
}

func (c *convertCmd) Run() error {
	if c.ParentTag == "" && len(c.CompilerTags) == 0 && len(c.RequiredTags) == 0 && len(c.InputTags) == 0 {
		return errors.New("no input tags specified")
	}
	if c.ParentTag == "" && (len(c.CompilerTags) > 0 || len(c.RequiredTags) > 0) {
		return errors.New("cannot have compiler or required tags without a parent to bind them to")
	}
	utag, err := importFiles(c.ParentTag, c.InputTags, c.RequiredTags, c.CompilerTags)
	if err != nil {
		return err
	}
	if err := writeFile(c.OutputFile, c.OutputFormat, c.ZlibCompress, *utag); err != nil {
		return err
	}
	return nil
}

func (p *printCmd) Run() error {
	if p.ParentTag == "" && len(p.CompilerTags) == 0 && len(p.RequiredTags) == 0 && len(p.InputTags) == 0 {
		return errors.New("no input tags specified")
	}
	if p.ParentTag == "" && (len(p.CompilerTags) > 0 || len(p.RequiredTags) > 0) {
		return errors.New("cannot have compiler or required tags without a parent to bind them to")
	}
	utag, err := importFiles(p.ParentTag, p.InputTags, p.RequiredTags, p.CompilerTags)
	if err != nil {
		return err
	}
	switch p.OutputFormat {
	//TODO pretty print in other formats
	case "json":
		output_buf, err := utag.ToJSON()
		if err != nil {
			return fmt.Errorf("uswid_input_tag.ToJSON(): %w", err)
		}
		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, []byte(output_buf), "", "    "); err != nil {
			return err
		}
		fmt.Println(prettyJSON.String())
	default:
		return fmt.Errorf("cannot pretty print %s format", p.OutputFormat)
	}
	return nil
}

func (g *generateTagIDCmd) Run() {
	fmt.Println(uuid.NewSHA1(uuid.NameSpaceDNS, []byte(g.UuidgenName)))
}

func recursivePlantUML(stringBuilder *strings.Builder, beenThere []bool, uid *uswid.UswidSoftwareIdentity, i int) {
	beenThere[i] = true
	currentId := uid.Identities[i]
	stringBuilder.WriteString(`object "`)
	stringBuilder.WriteString(currentId.SoftwareName)
	stringBuilder.WriteString(`" as `)
	stringBuilder.WriteString(strconv.Itoa(i))
	stringBuilder.WriteRune('\n')
	if currentId.Links == nil {
		return
	}
	for _, link := range *currentId.Links {
		//TODO comparing the string values is quite slow, but the values are probably saved as strings inside link.Rel
		if link.Rel.String() == swid.NewRel(swid.RelRequires).String() || link.Rel.String() == swid.NewRel(swid.RelCompiler).String() {
			for index, id := range uid.Identities {
				// speed it up a bit by ignoring tag's where we have already been
				if beenThere[index] {
					continue
				}
				if id.TagID.URI() == link.Href {
					recursivePlantUML(stringBuilder, beenThere[:], uid, index)
					stringBuilder.WriteByte('"')
					stringBuilder.WriteString(strconv.Itoa(index))
					stringBuilder.WriteString(`" --> "`)
					stringBuilder.WriteString(strconv.Itoa(i))
					stringBuilder.WriteByte('"')
					stringBuilder.WriteString("\n")
				}
			}
		}
	}
}

func ToPlantUML(id *uswid.UswidSoftwareIdentity) ([]byte, error) {
	var strbuilder strings.Builder
	beenThere := make([]bool, len(id.Identities))
	strbuilder.WriteString("@startuml\n")
	for i, been := range beenThere {
		if been {
			continue
		}
		recursivePlantUML(&strbuilder, beenThere[:], id, i)
	}
	strbuilder.WriteString("@enduml")
	return []byte(strbuilder.String()), nil
}

func writeFile(filename string, fileFormat string, zlibCompress bool, utag uswid.UswidSoftwareIdentity) error {
	// check file extension and put CoSWID tags into output file
	var output_buf []byte

	var err error
	switch fileFormat {
	case "json":
		output_buf, err = utag.ToJSON()
	case "xml":
		output_buf, err = utag.ToXML()
	case "cbor":
		output_buf, err = utag.ToCBOR(zlibCompress)
	case "uswid":
		output_buf, err = utag.ToUSWID(zlibCompress)
	case "plantuml":
		output_buf, err = ToPlantUML(&utag)
	case "":
		of_parts := strings.Split(filename, ".")
		if len(of_parts) < 2 {
			return errors.New("no file extension found")
		}
		switch of_parts[len(of_parts)-1] {
		case "json":
			output_buf, err = utag.ToJSON()
		case "xml":
			output_buf, err = utag.ToXML()
		case "cbor":
			output_buf, err = utag.ToCBOR(zlibCompress)
		case "uswid":
			output_buf, err = utag.ToUSWID(zlibCompress)
		case "plantuml":
			output_buf, err = ToPlantUML(&utag)
		default:
			return errors.New("could not guess file format by file extension")
		}
	default:
		return errors.New("unknown file format")
	}
	if err != nil {
		return err
	}

	if filename == "-" {
		fmt.Print(output_buf)
	} else {
		if err := ioutil.WriteFile(filename, output_buf, 0644); err != nil {
			return err
		}
	}
	return nil
}

func importFiles(parentTag string, inputFiles []string, requiredTags []string, compilerTags []string) (*uswid.UswidSoftwareIdentity, error) {
	var utag uswid.UswidSoftwareIdentity
	if parentTag != "" {
		if err := utag.FromFile(parentTag); err != nil {
			return nil, err
		}
	}
	for _, input_file_path := range requiredTags {
		index := len(utag.Identities)
		if err := utag.FromFile(input_file_path); err != nil {
			return nil, err
		}

		// if there is a parentfile specified, we create a link between that CoSWID tag and the first of each file, which we assume to be a parent CoSWID Tag above all others
		link, err := swid.NewLink(utag.Identities[index].TagID.URI(), *swid.NewRel(swid.RelRequires))
		if err != nil {
			return nil, err
		}
		if err := utag.Identities[0].AddLink(*link); err != nil {
			return nil, err
		}
	}
	for _, input_file_path := range compilerTags {
		index := len(utag.Identities)
		if err := utag.FromFile(input_file_path); err != nil {
			return nil, err
		}

		// if there is a parentfile specified, we create a link between that CoSWID tag and the first of each file, which we assume to be a parent CoSWID Tag above all others
		link, err := swid.NewLink(utag.Identities[index].TagID.URI(), *swid.NewRel(swid.RelCompiler))
		if err != nil {
			return nil, err
		}
		if err := utag.Identities[0].AddLink(*link); err != nil {
			return nil, err
		}
	}
	for _, input_file_path := range inputFiles {
		if err := utag.FromFile(input_file_path); err != nil {
			return nil, err
		}
	}
	return &utag, nil
}
