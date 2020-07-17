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

type Int64 struct {
	Value  int64
	Exists bool
}

// FromInt64 creates a non-null Int64.
// It is inlined by the compiler.
func FromInt64(n int64) Int64 {
	return Int64{
		Value:  n,
		Exists: true,
	}
}

func (i *Int64) UnmarshalJSON(data []byte) error {
	if string(data) == `null` {
		*i = Int64{}
		return nil
	}
	data = jsonutil.UnquoteJSON(data)
	if len(data) == 0 {
		*i = Int64{}
		return nil
	}
	n, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return err
	}
	*i = Int64{
		Value:  n,
		Exists: true,
	}
	return nil
}

// int64Codec is a jsoniter encoder/decoder for integer values
type int64Codec struct{}

// Decode implements jsoniter.ValDecoder interface
func (*int64Codec) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	const opName = "ReadNullInt64"
	switch iter.WhatIsNext() {
	case jsoniter.NilValue:
		iter.ReadNil()
		*((*Int64)(ptr)) = Int64{}
	case jsoniter.StringValue:
		s := iter.ReadStringAsSlice()
		if len(s) == 0 {
			*((*Int64)(ptr)) = Int64{}
			return
		}
		n, err := strconv.ParseInt(string(s), 10, 64)
		if err != nil {
			iter.ReportError(opName, err.Error())
			return
		}
		*((*Int64)(ptr)) = Int64{
			Value:  n,
			Exists: true,
		}
	default:
		iter.Skip()
		iter.ReportError(opName, "invalid null int64 value")
	}
}

// Encode implements jsoniter.ValEncoder interface
func (*int64Codec) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	if i := (*Int64)(ptr); i.Exists {
		stream.WriteInt64(i.Value)
	} else {
		stream.WriteNil()
	}
}

// IsEmpty implements jsoniter.ValEncoder interface
// WARNING: This considers `null` values as empty and omits them
func (*int64Codec) IsEmpty(ptr unsafe.Pointer) bool {
	return !((*Int64)(ptr)).Exists
}