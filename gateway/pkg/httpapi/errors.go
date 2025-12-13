package httpapi

import "github.com/gin-gonic/gin"

// APIError defines the unified error payload for gateway responses.
type APIError struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// ErrorResponse is kept for compatibility with existing swagger annotations.
// It aliases the unified APIError shape.
type ErrorResponse = APIError

func respondError(c *gin.Context, status int, code, message string, details interface{}) {
	c.JSON(status, APIError{
		Code:    code,
		Message: message,
		Details: details,
	})
}
