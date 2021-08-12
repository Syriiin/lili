# lili

lili is a simple service api for storing text files in the cloud.

[liliview](https://github.com/Syriiin/liliview) is a web app frontend for lili.

## setup

create a `.env` file with `SECRET_KEY` and `DATABASE_URL` env vars.
```
SECRET_KEY= // generate with something like golang's "crypto/rand" package
DATABASE_URL=postgres://lili:lili@db:5432/lili
```

when running for the first time, execute the `lili.sql` file manually to create the tables.

## why?

i have a terrible habit of keeping uncommitted text files full of notes in repos and after spending way way way too long recovering some from a suddenly dead hard drive, i decided i wanted a slightly more robust solution.

also i wanted a simple project to learn golang with.

## why "lili"?

notes -> ~~gotes~~ -> notepad -> lilypad -> lilipad -> lili
