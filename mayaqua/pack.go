package mayaqua

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

// We use 64bit only considering golang will do the dirty work for us on 32bit machines
const (
	MAX_VALUE_SIZE       = (384 * 1024 * 1024) // Maximum Data size that can be stored in a single VALUE
	MAX_VALUE_NUM        = uint32(262144)      // Maximum VALUE number that can be stored in a single ELEMENT
	MAX_ELEMENT_NAME_LEN = 63                  // The length of the name that can be attached to the ELEMENT
	MAX_ELEMENT_NUM      = 262144              // Maximum ELEMENT number that can be stored in a single PACK
	MAX_PACK_SIZE        = (512 * 1024 * 1024) // Maximum size of a serialized PACK
)

// ValueType type of a value
type ValueType uint32

const (
	VALUE_INT    = ValueType(0) // Integer type
	VALUE_DATA   = ValueType(1) // Data type
	VALUE_STR    = ValueType(2) // ANSI string type
	VALUE_UNISTR = ValueType(3) // Unicode string type
	VALUE_INT64  = ValueType(4) // 64 bit integer type

)

var (
	NUMBER_EXCEEDS   = errors.New("Number exceeds")
	SIZE_OVER        = errors.New("Size over")
	INVALID_TYPE     = errors.New("Invalid type")
	SAME_NAME_EXISTS = errors.New("Same name exists")
	ZERO_NUM_VALUE   = errors.New("Zero num value")
)

// Value structure
type Value struct {
	// Size       uint32 // we don't use here
	IntValue   uint32
	Int64Value uint64
	Data       []uint8
	Str        string
	UniStr     string
}

// Element structure
type Element struct {
	Name string
	Type ValueType
	// NumValue uint32
	Values []Value

	JsonHint_IsArray    bool
	JsonHint_IsBool     bool
	JsonHint_IsDateTime bool
	JsonHint_IsIP       bool
	JsonHint_GroupName  string
}

// NumValue number of values
func (e *Element) NumValue() uint32 {
	return uint32(len(e.Values))
}

// Pack structure
type Pack struct {
	Elements []*Element

	JSONSubitemNames          []string
	CurrentJsonHint_GroupName string
}

// ReadPack read pack from buf
func ReadPack(r io.Reader) (*Pack, error) {
	pack := &Pack{}
	num := uint32(0)
	if err := binary.Read(r, binary.BigEndian, &num); nil != err {
		return nil, err
	}
	if num > MAX_ELEMENT_NUM {
		return nil, NUMBER_EXCEEDS
	}

	pack.Elements = make([]*Element, 0, num)

	for i := uint32(0); i < num; i++ {
		if e, err := ReadElement(r); nil != err {
			return nil, err
		} else {
			if err := pack.AddElement(e); nil != err {
				return nil, err
			}
		}
	}

	return pack, nil
}

// ReadElement read element from a reader
func ReadElement(r io.Reader) (e *Element, err error) {
	e = &Element{}
	if e.Name, err = ReadBufStr(r); nil != err {
		return nil, err
	}

	if err = binary.Read(r, binary.BigEndian, &e.Type); nil != err {
		return nil, err
	}

	n := uint32(0)
	if err = binary.Read(r, binary.BigEndian, &n); nil != err {
		return nil, err
	} else if n > MAX_VALUE_NUM {
		return nil, NUMBER_EXCEEDS
	}

	e.Values = make([]Value, 0, n)
	for i := uint32(0); i < n; i++ {
		if v, err := ReadValue(r, e.Type); nil != err {
			return nil, err
		} else {
			e.Values = append(e.Values, v)
		}
	}

	return e, nil
}

// ReadValue read value from a reader
func ReadValue(r io.Reader, t ValueType) (v Value, err error) {
	switch t {
	case VALUE_INT:
		if err = binary.Read(r, binary.BigEndian, &v.IntValue); nil != err {
			return v, err
		}
	case VALUE_INT64:
		if err = binary.Read(r, binary.BigEndian, &v.Int64Value); nil != err {
			return v, err
		}
	case VALUE_DATA:
		s := uint32(0)
		if err = binary.Read(r, binary.BigEndian, &s); nil != err {
			return v, err
		} else if s > MAX_VALUE_SIZE {
			return v, SIZE_OVER
		}
		v.Data = make([]uint8, int(s))
		if _, err = io.ReadFull(r, v.Data); nil != err {
			return v, err
		}
	case VALUE_STR:
		s := uint32(0)
		if err = binary.Read(r, binary.BigEndian, &s); nil != err {
			return v, err
		} else if s > MAX_VALUE_SIZE-1 {
			return v, SIZE_OVER
		}
		d := make([]uint8, int(s))
		if _, err = io.ReadFull(r, d); nil != err {
			return v, err
		}
		v.Str = string(d)
	case VALUE_UNISTR:
		panic("unimplemented")
	default:
		return v, INVALID_TYPE
	}

	return v, nil
}

// AddElement add element
func (p *Pack) AddElement(e *Element) error {
	if len(p.Elements) >= MAX_ELEMENT_NUM {
		return NUMBER_EXCEEDS
	}
	if nil != p.GetElement(e.Name, ValueType(INFINITE)) {
		return SAME_NAME_EXISTS
	}

	if e.NumValue() == 0 {
		return ZERO_NUM_VALUE
	}

	e.JsonHint_GroupName = p.CurrentJsonHint_GroupName
	p.Elements = append(p.Elements, e)
	return nil
}

// GetElement get element with type
func (p *Pack) GetElement(name string, t ValueType) *Element {
	n := strings.ToUpper(name)
	for _, e := range p.Elements {
		if n == strings.ToUpper(e.Name) && (t == ValueType(INFINITE) || t == e.Type) {
			return e
		}
	}
	return nil
}

// GetInt get integer
func (p *Pack) GetInt(name string) uint32 {
	return p.GetIntEx(name, 0)
}

// GetIntEx get integer with index
func (p *Pack) GetIntEx(name string, index uint32) uint32 {
	if e := p.GetElement(name, VALUE_INT); nil == e {
		return 0
	} else {
		return e.GetIntValue(index)
	}
}

// GetStr get string
func (p *Pack) GetStr(name string) string {
	return p.GetStrEx(name, 0)
}

// GetStrEx get string with index
func (p *Pack) GetStrEx(name string, index uint32) string {
	if e := p.GetElement(name, VALUE_STR); nil == e {
		return ""
	} else {
		return e.GetStrValue(index)
	}
}

// GetDataEx get data
func (p *Pack) GetData(name string) []byte {
	return p.GetDataEx(name, 0)
}

// GetDataEx get data with index
func (p *Pack) GetDataEx(name string, index uint32) []byte {
	if e := p.GetElement(name, VALUE_DATA); nil == e {
		return nil
	} else {
		return e.GetDataValue(index)
	}
}

// GetDataSize get data size
func (p *Pack) GetDataSize(name string) uint32 {
	return p.GetDataSizeEx(name, 0)
}

// GetDataSizeEx get data size with index
func (p *Pack) GetDataSizeEx(name string, index uint32) uint32 {
	if e := p.GetElement(name, VALUE_DATA); nil == e {
		return 0
	} else {
		return e.GetDataValueSize(index)
	}
}

// GetIntValue get integer value
func (e *Element) GetIntValue(index uint32) uint32 {
	if index >= e.NumValue() {
		return 0
	}
	return e.Values[index].IntValue
}

// GetStrValue get string value
func (e *Element) GetStrValue(index uint32) string {
	if index >= e.NumValue() {
		return ""
	}
	return e.Values[index].Str
}

// GetDataValue get data value
func (e *Element) GetDataValue(index uint32) []byte {
	if index >= e.NumValue() {
		return nil
	}
	return e.Values[index].Data
}

// GetDataValueSize get data value size
func (e *Element) GetDataValueSize(index uint32) uint32 {
	if index >= e.NumValue() {
		return 0
	}
	return uint32(len(e.Values[index].Data))
}

// AddStr add string value
func (p *Pack) AddStr(name string, str string) *Element {
	e := &Element{
		Name:   name,
		Type:   VALUE_STR,
		Values: []Value{{Str: str}},
	}
	if err := p.AddElement(e); nil != err {
		return nil
	}
	return e
}

// AddBool add bool (as integer)
func (p *Pack) AddBool(name string, b bool) *Element {
	v := uint32(0)
	if b {
		v = uint32(1)
	}
	e := p.AddInt(name, v)
	if nil != e {
		e.JsonHint_IsBool = true
	}
	return e
}

// AddInt add integer value
func (p *Pack) AddInt(name string, i uint32) *Element {
	e := &Element{
		Name:   name,
		Type:   VALUE_INT,
		Values: []Value{{IntValue: i}},
	}
	if err := p.AddElement(e); nil != err {
		return nil
	}
	return e
}

// AddData add data value
func (p *Pack) AddData(name string, data []byte) *Element {
	e := &Element{
		Name:   name,
		Type:   VALUE_DATA,
		Values: []Value{{Data: data}},
	}
	if err := p.AddElement(e); nil != err {
		return nil
	}
	return e
}

// AddIp32 add ipv4
func (p *Pack) AddIp32(name string, ip uint32) *Element {
	if e := p.AddBool(name+"@ipv6_bool", false); nil != e {
		e.JsonHint_IsIP = true
	}
	if e := p.AddData(name+"@ipv6_array", make([]byte, 16)); nil != e {
		e.JsonHint_IsIP = true
	}
	if e := p.AddInt(name+"@ipv6_scope_id", 0); nil != e {
		e.JsonHint_IsIP = true
	}

	// ? BigEndian?
	if e := p.AddInt(name, ip); nil != e {
		e.JsonHint_IsIP = true
		return e
	}

	return nil
}

// ToBuf To buffer
func (p *Pack) ToBuf() ([]byte, error) {
	b := &bytes.Buffer{}
	if err := binary.Write(b, binary.BigEndian, uint32(len(p.Elements))); nil != err {
		return nil, err
	}
	for _, e := range p.Elements {
		if err := e.Write(b); nil != err {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

func (e *Element) Write(w io.Writer) error {
	if err := WriteBufStr(w, e.Name); nil != err {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, e.Type); nil != err {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, e.NumValue()); nil != err {
		return err
	}
	for _, v := range e.Values {
		if err := v.Write(w, e.Type); nil != err {
			return err
		}
	}
	return nil
}

func (v *Value) Write(w io.Writer, t ValueType) error {
	switch t {
	case VALUE_INT:
		return binary.Write(w, binary.BigEndian, v.IntValue)
	case VALUE_INT64:
		return binary.Write(w, binary.BigEndian, v.Int64Value)
	case VALUE_DATA:
		s := int32(len(v.Data))
		if err := binary.Write(w, binary.BigEndian, s); nil != err {
			return err
		}
		_, err := w.Write(v.Data)
		return err
	case VALUE_STR:
		b := []byte(v.Str)
		s := uint32(len(b))
		if err := binary.Write(w, binary.BigEndian, s); nil != err {
			return err
		}
		_, err := w.Write(b)
		return err
	case VALUE_UNISTR:
		panic("unimplemented")
	default:
		return INVALID_TYPE
	}
}
