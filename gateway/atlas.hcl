env "dev" {
  url = getenv("DATABASE_URL")

  migration {
    dir = "file://db/migrations"
  }
}