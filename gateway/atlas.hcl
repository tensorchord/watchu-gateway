env "dev" {
  url = env("DATABASE_URL")

  migration {
    dir = "file://db/migrations"
  }
}