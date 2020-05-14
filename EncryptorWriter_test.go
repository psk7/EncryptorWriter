package EncryptorWriter

import (
	"reflect"
	"testing"
)

func Test_appendData(t *testing.T) {
	type args struct {
		buf  []byte
		data []byte
	}
	tests := []struct {
		name        string
		args        args
		wantNewBuf  []byte
		wantRemains []byte
	}{
		{name: testing.CoverMode(), args: struct {
			buf  []byte
			data []byte
		}{buf: make([]byte, 4)[0:0], data: []byte{1}}, wantNewBuf: []byte{1}, wantRemains: nil},

		{name: testing.CoverMode(), args: struct {
			buf  []byte
			data []byte
		}{buf: make([]byte, 4)[0:0], data: []byte{1, 2, 3, 4}}, wantNewBuf: []byte{1, 2, 3, 4}, wantRemains: nil},

		{name: testing.CoverMode(), args: struct {
			buf  []byte
			data []byte
		}{buf: make([]byte, 4)[0:0], data: []byte{1, 2, 3, 4, 5, 6}}, wantNewBuf: []byte{1, 2, 3, 4}, wantRemains: []byte{5, 6}},

		{name: testing.CoverMode(), args: struct {
			buf  []byte
			data []byte
		}{buf: make([]byte, 4)[0:0], data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}}, wantNewBuf: []byte{1, 2, 3, 4}, wantRemains: []byte{5, 6, 7, 8, 9}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNewBuf, gotRemains := appendData(tt.args.buf, tt.args.data)
			if !reflect.DeepEqual(gotNewBuf, tt.wantNewBuf) {
				t.Errorf("appendData() gotNewBuf = %v, want %v", gotNewBuf, tt.wantNewBuf)
			}
			if !reflect.DeepEqual(gotRemains, tt.wantRemains) {
				t.Errorf("appendData() gotRemains = %v, want %v", gotRemains, tt.wantRemains)
			}
		})
	}
}
