package ingest

import "reflect"

var (
	httpRequestCols   = mustColumnsFromStruct[HTTPRequestEvent]()
	httpResponseCols  = mustColumnsFromStruct[HTTPResponseEvent]()
	execEventCols     = mustColumnsFromStruct[ExecEvent]()
	mcpSTDIOEventCols = mustColumnsFromStruct[MCPSTDIOEvent]()
)

func mustColumnsFromStruct[T any]() []string {
	var zero T
	structType := reflect.TypeOf(zero)
	if structType.Kind() == reflect.Pointer {
		structType = structType.Elem()
	}

	if structType.Kind() != reflect.Struct {
		panic("mustColumnsFromStruct requires a struct type")
	}

	cols := make([]string, 0, structType.NumField())
	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		tag := field.Tag.Get("db")
		if tag == "" || tag == "-" {
			panic("missing db tag on field " + structType.Name() + "." + field.Name)
		}
		cols = append(cols, tag)
	}

	return cols
}
