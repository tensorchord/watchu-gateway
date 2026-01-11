module github.com/tensorchord/watchu/skill-runner

go 1.25.3

require (
	github.com/google/uuid v1.6.0
	github.com/tensorchord/watchu/gateway v0.0.0-00010101000000-000000000000
)

replace github.com/tensorchord/watchu/gateway => ../gateway
