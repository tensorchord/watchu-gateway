package ingest

import "reflect"

var (
	httpRequestCols  = mustColumnsFromStruct[HTTPRequestEvent]()
	httpResponseCols = mustColumnsFromStruct[HTTPResponseEvent]()
	execEventCols    = mustColumnsFromStruct[ExecEvent]()
)

func mustColumnsFromStruct[T any]() []string {
	var zero T
	typ := reflect.TypeOf(zero)
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}

	if typ.Kind() != reflect.Struct {
		panic("mustColumnsFromStruct requires a struct type")
	}

	cols := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("db")
		if tag == "" || tag == "-" {
			panic("missing db tag on field " + typ.Name() + "." + field.Name)
		}
		cols = append(cols, tag)
	}

	return cols
}
