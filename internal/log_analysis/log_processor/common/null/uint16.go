// nolint: dupl
package null

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"strconv"
	"unsafe"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/jsonutil"
)

type Uint16 struct {
	Value  uint16
	Exists bool
}

// FromUint16 creates a non-null Uint16.
// It is inlined by the compiler.
func FromUint16(n uint16) Uint16 {
	return Uint16{
		Value:  n,
		Exists: true,
	}
}

func (u *Uint16) UnmarshalJSON(data []byte) error {
	if string(data) == `null` {
		*u = Uint16{}
		return nil
	}
	data = jsonutil.UnquoteJSON(data)
	if len(data) == 0 {
		*u = Uint16{}
		return nil
	}
	n, err := strconv.ParseUint(string(data), 10, 16)
	if err != nil {
		return err
	}
	*u = Uint16{
		Value:  uint16(n),
		Exists: true,
	}
	return nil
}

// int64Codec is a jsoniter encoder/decoder for integer values
type uint16Codec struct{}

// Decode implements jsoniter.ValDecoder interface
func (*uint16Codec) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	const opName = "ReadNullUint16"
	switch iter.WhatIsNext() {
	case jsoniter.NilValue:
		iter.ReadNil()
		*((*Uint16)(ptr)) = Uint16{}
	case jsoniter.StringValue:
		s := iter.ReadStringAsSlice()
		if len(s) == 0 {
			*((*Uint16)(ptr)) = Uint16{}
			return
		}
		n, err := strconv.ParseUint(string(s), 10, 16)
		if err != nil {
			iter.ReportError(opName, err.Error())
			return
		}
		*((*Uint16)(ptr)) = Uint16{
			Value:  uint16(n),
			Exists: true,
		}
	default:
		iter.Skip()
		iter.ReportError(opName, "invalid null uint16 value")
	}
}

// Encode implements jsoniter.ValEncoder interface
func (*uint16Codec) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	if u := (*Uint16)(ptr); u.Exists {
		stream.WriteUint16(u.Value)
	} else {
		stream.WriteNil()
	}
}

// IsEmpty implements jsoniter.ValEncoder interface
// WARNING: This considers `null` values as empty and omits them
func (*uint16Codec) IsEmpty(ptr unsafe.Pointer) bool {
	return !((*Uint16)(ptr)).Exists
}
