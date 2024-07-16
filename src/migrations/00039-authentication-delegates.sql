CREATE TABLE IF NOT EXISTS "authentication delegate" (
	"id" SERIAL NOT NULL PRIMARY KEY
,	"created at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
,	"modified at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
,	"uuid" VARCHAR(255) NOT NULL UNIQUE
,	"public key" VARCHAR(255) NULL
);
