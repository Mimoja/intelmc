package intelmc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

type Microcode struct {
	Header             Header
	Date Date
	CalculatedChecksum uint32
	Platforms          []uint8
	HeaderExtra        *ExtraHeader
	Encryption         *RSAHeader
	HeaderExtended     *ExtendedHeader
	Raw []byte
}

//Taken from MCE.py
type Header struct {
	HeaderVersion      uint32    // 0x00 00000001 (Pattern)
	UpdateRevision     uint32    // 0x04 Signed to signify PRD/PRE
	Year               uint16    // 0x08
	Day                uint8     // 0x0A
	Month              uint8     // 0x0B
	ProcessorSignature uint32    // 0x0C
	Checksum           uint32    // 0x10 OEM validation only
	LoaderRevision     uint32    // 0x14 00000001 (Pattern)
	PlatformIDs        uint8     // 0x18 Supported Platforms
	Reserved0          [3]uint8  // 0x19 00 * 3 (Pattern)
	DataSize           uint32    // 0x1C Extra + Patch
	TotalSize          uint32    // 0x20 Header + Extra + Patch + Extended
	Reserved1          [12]uint8 // 0x24 00 * 12 (Pattern)
}
type Date struct {
	Year               uint16   // 0x08
	Day                uint8     // 0x0A
	Month              uint8     // 0x0B
}

type ExtraHeader struct {
	ModuleType              uint16    // 0x00 0000 (always)
	ModuleSubType           uint16    // 0x02 0000 (always)
	ModuleSize              uint32    // 0x04 dwords
	Flags                   uint16    // 0x08 0 RSA Signed, 1-31 Reserved
	RSAKeySize              uint16    // 0x0A 1K multiple (2 * 1024 = 2048)
	UpdateRevision          uint32    // 0x0C Signed to signify PRD/PRE
	VCN                     uint32    // 0x10 Version Control Number
	MultiPurpose1           uint32    // 0x14 dwords from Extra, UpdateSize, Empty etc
	Day                     uint8     // 0x18
	Month                   uint8     // 0x19
	Year                    uint16    // 0x1A
	UpdateSize              uint32    // 0x1C dwords from Extra without encrypted padding
	ProcessorSignatureCount uint32    // 0x20 max is 8 (8 * 0x4 = 0x20)
	ProcessorSignature0     uint32    // 0x24
	ProcessorSignature1     uint32    // 0x28
	ProcessorSignature2     uint32    // 0x2C
	ProcessorSignature3     uint32    // 0x30
	ProcessorSignature4     uint32    // 0x34
	ProcessorSignature5     uint32    // 0x38
	ProcessorSignature6     uint32    // 0x3C
	ProcessorSignature7     uint32    // 0x40
	MultiPurpose2           uint32    // 0x44 dwords from Extra + encrypted padding, UpdateSize, Platform, Empty
	SVN                     uint32    // 0x48 Security Version Number
	Reserved                [20]uint8 // 0x4C Reserved (00000000)
	Unknown                 [32]uint8 // 0x60
	//Variable length RSA block here
	// 0x184 0x14 --> SHA-1 or 0x20 --> SHA-256
	// 0x200 0x33 --> 0x13 = Unknown + 0x20 = SHA-256
}

type RSAHeader struct {
	RSAPublicKey []uint8
	RSAExponent  uint32
	RSASignature []uint8
}

type ExtendedHeader struct {
	ExtendedSignatureCount uint32    // 0x00
	ExtendedChecksum       uint32    // 0x04
	Reserved               [3]uint32 // 0x08
}

type ExtendedHeaderField struct {
	ProcessorSignature uint32 // 0x00
	PlatformIDs        uint32 // 0x04
	Checksum           uint32 // 0x08 replace CPUID, Platform, Checksum at Main Header w/o Extended
}

func CalculateChecksum(data []byte) uint32 {
	chk32 := 0

	for i := 0; i < len(data); i += 4 {
		chk32 += int(binary.LittleEndian.Uint32(data[i : i+4]))
	}
	return uint32(-chk32 & 0xFFFFFFFF)
}

func IntelPlatforms(cpuflags uint8) []uint8 {

	// 1995 - 1998
	if cpuflags == 0 {
		return []uint8{0}
	}

	platforms := []uint8{}

	for bit := uint8(0); bit < 8; bit++ {
		cpu_flag := cpuflags >> bit & 1
		if cpu_flag == 1 {
			platforms = append(platforms, bit)
		}
	}

	return platforms
}

func ParseMicrocodeExtraHeader(mcBytes []byte) (*ExtraHeader, error) {
	mce := ExtraHeader{}
	if len(mcBytes) < 0x80 {
		return nil, nil
	}

	err := binary.Read(bytes.NewReader(mcBytes), binary.LittleEndian, &mce)
	return &mce, err
}

func ParseMicrocodeHeader(mcBytes []byte) (*Header, error) {
	mc := Header{}
	err := binary.Read(bytes.NewReader(mcBytes), binary.LittleEndian, &mc)

	return &mc, err
}

func ParseMicrocode(mcBytes []byte) (*Microcode, error) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	m := Microcode{}
	mc, err := ParseMicrocodeHeader(mcBytes)
	if err != nil {
		log.Printf("Could not parse microcode header")
		return nil, err
	}

	m.Header = *mc

	bcdString := fmt.Sprintf("%x %x %x", mc.Year, mc.Month, mc.Day)
	fmt.Sscanf(bcdString, "%4d %2d %2d", &m.Date.Year, &m.Date.Month, &m.Date.Day)

	mcLength := 0x800
	if len(mcBytes) < mcLength {
		log.Print("Microcode is way shorter then expected")
		mcLength = len(mcBytes)
	}

	if mc.TotalSize != 0 {
		mcLength = int(mc.TotalSize)
	}

	m.CalculatedChecksum = CalculateChecksum(mcBytes[:mcLength])
	m.Platforms = IntelPlatforms(mc.PlatformIDs)

	mcExtraBytes := mcBytes[0x30:]

	mce, err := ParseMicrocodeExtraHeader(mcExtraBytes)
	if err != nil {
		log.Printf("Could not parse microcode extended header")
	}

	rsaBytes := mcExtraBytes[0x80:]
	rsa := RSAHeader{}

	if mce.ModuleSize == 0 {
		//TODO mce = nil
		log.Println("mce.ModuleSize == 0")
	} else if mce.ModuleSize == 0xA1 {
		rsa.RSAPublicKey = rsaBytes[:0x100]
		rsa.RSASignature = rsaBytes[0x100+0x4 : 0x100+0x4+0x100]
		rsa.RSAExponent = binary.LittleEndian.Uint32(rsaBytes[0x100 : 0x100+0x4])
		m.Encryption = &rsa
	} else if mce.ModuleSize == 0xE0 {
		rsa.RSAPublicKey = rsaBytes[:0x180]
		rsa.RSASignature = rsaBytes[0x180 : 0x180+0x180]
		rsa.RSAExponent = 0x10001
		m.Encryption = &rsa
	} else {
		log.Printf("Unknown Modules Size: 0x%08X", mce.ModuleSize)
	}

	// We still have space for an extended (!= extra) header
	if mc.TotalSize <= mc.DataSize+0x30 {
		extendedOffset := 0x30 + mc.DataSize
		mcex := ExtendedHeader{}
		binary.Read(bytes.NewReader(mcBytes[extendedOffset:]), binary.LittleEndian, &mcex)

		m.HeaderExtended = &mcex
		if mcex.ExtendedSignatureCount != 0 {
			log.Printf("Parsing the extra header is not supported (yet)")
			//taken from MCE.py
			/*
				ext_header_checksum = mc_hdr_ext.ExtendedChecksum
				ext_fields_count = mc_hdr_ext.ExtendedSignatureCount
				ext_header_size = ext_hdr_size + ext_fields_count * ext_fld_size # 20 intro bytes, 12 for each field
				ext_header_data = reading[mc_bgn + 0x30 + mc_hdr.DataSize:mc_bgn + 0x30 + mc_hdr.DataSize + ext_header_size]
				valid_ext_chk = checksum32(ext_header_data) # Extended Header + Fields Checksum

				mc_ext_field_off = mc_ext_off + ext_hdr_size
				for ext_idx in range(ext_fields_count) :
				mc_hdr_ext_field = get_struct(reading, mc_ext_field_off, Intel_MC_Header_Extended_Field)
				if param.print_hdr : mc_hdr_ext_field.mc_print()

				ext_mc_data = bytearray(mc_data) # Duplicate main Microcode container data for Extended replacements
				ext_mc_data[0xC:0x10] = struct.pack('<I', mc_hdr_ext_field.ProcessorSignature) # Extended CPUID
				ext_mc_data[0x10:0x14] = struct.pack('<I', mc_hdr_ext_field.Checksum) # Extended Checksum
				ext_mc_data[0x18:0x1C] = struct.pack('<I', mc_hdr_ext_field.PlatformIDs) # Extended Platform IDs

				ext_mc_path = os.path.join(mce_dir, 'Extended_%s_%d_%0.8X.temp' % (os.path.basename(in_file), ext_idx + 1, mc_hdr_ext_field.Checksum))
				temp_mc_paths.append(ext_mc_path) # Store Extended microcode binary path to parse once and delete at the end
				source.append(ext_mc_path) # Add Extended microcode binary path to the input files
				with open(ext_mc_path, 'wb') as ext_mc : ext_mc.write(ext_mc_data)

				mc_ext_field_off += ext_fld_size

				if param.print_hdr : continue # No more info to print, next MC of input file

				mc_name = 'cpu%0.5X_plat%0.2X_ver%0.8X_%s_%s_%0.8X' % (cpu_id, plat, patch_u, full_date, rel_file, mc_chk)
				mc_nr += 1

				# Check if any Reserved fields are not empty/0
				if mc_reserved_all != 0 :
				msg_i.append(col_m + '\nWarning: Microcode #%d has non-empty Reserved fields, please report it!' % mc_nr + col_e)
				if not param.mce_extr : copy_file_with_warn()
			*/
		}
	}

	m.Raw = mcBytes[:mcLength]
	return &m, nil
}
