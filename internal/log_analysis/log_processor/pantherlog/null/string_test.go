package null_test

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

import (
	"encoding/json"
	null2 "github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
)

func TestNullStringCodec(t *testing.T) {
	type A struct {
		Foo null2.String `json:"foo,omitempty"`
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":"bar"}`, &a)
		require.NoError(t, err)
		require.Equal(t, "bar", a.Foo.Value)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":"bar"}`, data)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":""}`, &a)
		require.NoError(t, err)
		require.Equal(t, "", a.Foo.Value)
		require.True(t, a.Foo.Exists)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{}`, data)
	}
	{
		a := null2.String{}
		err := jsoniter.UnmarshalFromString(`42`, &a)
		require.Error(t, err)
	}
	{
		a := A{}
		err := jsoniter.UnmarshalFromString(`{"foo":null}`, &a)
		require.NoError(t, err)
		require.Equal(t, "", a.Foo.Value)
		require.False(t, a.Foo.Exists)
		data, err := jsoniter.MarshalToString(&a)
		require.NoError(t, err)
		require.Equal(t, `{}`, data)
	}
	{
		s := null2.String{
			Value:  "foo",
			Exists: true,
		}
		data, err := jsoniter.MarshalToString(&s)
		require.NoError(t, err)
		require.Equal(t, `"foo"`, data)
	}
	{
		s := null2.String{}
		data, err := jsoniter.MarshalToString(&s)
		require.NoError(t, err)
		require.Equal(t, `null`, data)
	}
}
func TestNullStringUnmarshalJSON(t *testing.T) {
	type A struct {
		Foo null2.String `json:"foo,omitempty"`
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":"bar"}`), &a)
		require.NoError(t, err)
		require.Equal(t, "bar", a.Foo.Value)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":"bar"}`, string(data))
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":""}`), &a)
		require.NoError(t, err)
		require.Equal(t, "", a.Foo.Value)
		require.True(t, a.Foo.Exists)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":""}`, string(data))
	}
	{
		a := null2.String{}
		err := json.Unmarshal([]byte(`{}`), &a)
		require.Error(t, err)
	}
	{
		a := A{}
		err := json.Unmarshal([]byte(`{"foo":null}`), &a)
		require.NoError(t, err)
		require.Equal(t, "", a.Foo.Value)
		require.False(t, a.Foo.Exists)
		data, err := json.Marshal(&a)
		require.NoError(t, err)
		require.Equal(t, `{"foo":null}`, string(data))
	}
}
func TestFromString(t *testing.T) {
	{
		s := null2.FromString("")
		require.Equal(t, null2.String{Exists: true}, s)
	}
	{
		s := null2.FromString("foo")
		require.Equal(t, null2.String{Value: "foo", Exists: true}, s)
	}
}
func TestStringIsNull(t *testing.T) {
	{
		s := null2.String{}
		require.True(t, s.IsNull())
	}
	{
		s := null2.FromString("foo")
		require.False(t, s.IsNull())
	}
}
func TestNullStringString(t *testing.T) {
	{
		s := null2.String{}
		require.Equal(t, "", s.String())
	}
	{
		s := null2.String{
			Exists: true,
		}
		require.Equal(t, "", s.String())
	}
	{
		s := null2.String{
			Value:  "foo",
			Exists: true,
		}
		require.Equal(t, "foo", s.String())
	}
}

func BenchmarkNullString(b *testing.B) {
	data := []byte(`{"foo":"bar","bar":"baz","baz":null}`)
	// nolint:lll
	data12 := []byte(`{"f01":"01","f02":"02","f03":"03","f04":"04","f05":"05","f06":"06","f07":"07","f08":"08","f09":"09","f10":"10","f11":"11","f12":null}`)
	type A struct {
		Foo null2.String `json:"foo,omitempty"`
		Bar null2.String `json:"bar,omitempty"`
		Baz null2.String `json:"baz,omitempty"`
	}
	type B struct {
		Foo *string `json:"foo,omitempty"`
		Bar *string `json:"bar,omitempty"`
		Baz *string `json:"baz,omitempty"`
	}
	type DozenFieldsA struct {
		F01 null2.String `json:"f01,omitempty"`
		F02 null2.String `json:"f02,omitempty"`
		F03 null2.String `json:"f03,omitempty"`
		F04 null2.String `json:"f04,omitempty"`
		F05 null2.String `json:"f05,omitempty"`
		F06 null2.String `json:"f06,omitempty"`
		F07 null2.String `json:"f07,omitempty"`
		F08 null2.String `json:"f08,omitempty"`
		F09 null2.String `json:"f09,omitempty"`
		F10 null2.String `json:"f10,omitempty"`
		F11 null2.String `json:"f11,omitempty"`
		F12 null2.String `json:"f12,omitempty"`
	}
	type DozenFieldsB struct {
		F01 *string `json:"f01,omitempty"`
		F02 *string `json:"f02,omitempty"`
		F03 *string `json:"f03,omitempty"`
		F04 *string `json:"f04,omitempty"`
		F05 *string `json:"f05,omitempty"`
		F06 *string `json:"f06,omitempty"`
		F07 *string `json:"f07,omitempty"`
		F08 *string `json:"f08,omitempty"`
		F09 *string `json:"f09,omitempty"`
		F10 *string `json:"f10,omitempty"`
		F11 *string `json:"f11,omitempty"`
		F12 *string `json:"f12,omitempty"`
	}

	b.ReportAllocs()
	b.Run("NullString Unmarshal 3 fields", func(b *testing.B) {
		iter := jsoniter.ConfigDefault.BorrowIterator(nil)
		for i := 0; i < b.N; i++ {
			v := A{}
			iter.ResetBytes(data)
			iter.ReadVal(&v)
			if iter.Error != nil {
				b.Error(iter.Error)
			}
		}
	})
	b.Run("*string Unmarshal 3 fields", func(b *testing.B) {
		iter := jsoniter.ConfigDefault.BorrowIterator(nil)
		for i := 0; i < b.N; i++ {
			v := B{}
			iter.ResetBytes(data)
			iter.ReadVal(&v)
			if iter.Error != nil {
				b.Error(iter.Error)
			}
		}
	})
	b.Run("NullString Marshal 3 fields", func(b *testing.B) {
		a := A{
			Foo: null2.String{
				Value:  "foo",
				Exists: true,
			},
			Bar: null2.String{
				Value:  "bar",
				Exists: true,
			},
		}
		for i := 0; i < b.N; i++ {
			_, _ = jsoniter.Marshal(&a)
		}
	})
	b.Run("*string Marshal 3 fields", func(b *testing.B) {
		foo := "foo"
		bar := "bar"
		v := B{
			Foo: &foo,
			Bar: &bar,
		}
		for i := 0; i < b.N; i++ {
			_, _ = jsoniter.Marshal(&v)
		}
	})
	b.Run("NullString Unmarshal 12 fields", func(b *testing.B) {
		iter := jsoniter.ConfigDefault.BorrowIterator(nil)
		for i := 0; i < b.N; i++ {
			v := DozenFieldsA{}
			iter.ResetBytes(data12)
			iter.ReadVal(&v)
			if iter.Error != nil {
				b.Error(iter.Error)
			}
		}
	})
	b.Run("*string Unmarshal 12 fields", func(b *testing.B) {
		iter := jsoniter.ConfigDefault.BorrowIterator(nil)
		for i := 0; i < b.N; i++ {
			v := DozenFieldsB{}
			iter.ResetBytes(data12)
			iter.ReadVal(&v)
			if iter.Error != nil {
				b.Error(iter.Error)
			}
		}
	})
}
