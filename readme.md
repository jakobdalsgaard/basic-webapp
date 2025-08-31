The Perhaps Not So Basic Webapp
===============================

Example of a very basic webapp skeleton using Axum. Focus has been
ease of implementation using few technologies, but using them good.

* Axum based, with Askama templates
* Postgres backend
* Auth scheme _is_ implemented - just add data :-)

The default setup of this application requires unix domain socket
access to the Postgres database - by authenticating the OS user
running the application. This is by far the easiest - it also
happens to be extremely secure.

So, assuming the application is to be run as user 'jakob' - then,
as Postgres admin, in psql do:

```sql
create user jakob;
create database basic_webapp;
\c basic_webapp;
grant all on schema public to jakob;
create extension pgcrypto;
```

In short, this will:

1.  Create a database user without password, this user will not be able to connect to Postgres by any means requiring a password; such as, very normally, over a TCP connection.
2.  Create a database by the name `basic_webapp`
3.  Connect to said database
4.  Grant all permissions to the user just created; this can be trimmed, and should be for a production setup. However the correct setup will rely on the full database schema and functionality of the application. This is just a sketch application.
5.  Add the pgcrypto extension, used for the authorization scheme implemented.

Then edit the `pg_hba.conf` file for the Postgres installation and add:

```
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   basic_webapp    jakob                                   peer
```

Afterwards, as Postgres admin do:

```sql
select pg_reload_conf();
```

Check that the 'jakob' user can access the database by use of the psql tool:

```bash
$ psql basic_webapp
```

(Ctrl-D to exit).

With this working, the basic database can be created (and loaded with some very basic data). So, change to the schema directory and do:

```
make create
```

This will create tables and insert some basic data. Then change one directory up -- to be in the main project directory. You may now build the application:

```
cargo build
```

Then (or instead) go for run:

```
RUST_LOG=info cargo run --bin basic-webapp -- --config=etc/test.toml
```

The application will tell you that it's running and the janitor function (which deletes obsolete access tokens from memory) will periodically inform you that it is running. If you want the possibility of serving compressed Javascript and Stylesheet static file, then go to the `static` directory and run `make` -- this will create .gz files and the webapp will automatically pick them up (make sure to rerun make if you edit the .js and .css files).

Fire up a browser and head to [http://localhost:3080/](http://localhost:3080/) -- for a view of the frontpage; you can log in and log out; see the default account credentials in `scheme/create-db.sql`.

Prometheus metrics for the application are available on port 3050 (but only from localhost ipv6 by configuration in the application).

## Future improvements

* Bind to all sockets with SO_REUSEADDR; this will enable seamless upgrade with no downtime.
* Implement support for rustls and support for getting the client address via an HTTP header for when running behind HAProxy, Nginx, Envoy or similar.
* Look into better parallalization of maintaing the access token in-memory map.

