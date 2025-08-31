
create table account_state (
	id serial primary key,
	ident text not null unique,
	name text not null
);

insert into account_state (ident, name) values 
  ('valid', 'Valid'), ('suspended', 'Suspended');

create table account (
	id serial primary key,
	name text not null,
	username text not null,
	password text,
	state integer not null references account_state
);

insert into account (name, username, password, state)
   values ('Test User', 'test@test.com', crypt('1A2B3C4D5E', gen_salt('md5')), (select id from account_state where ident='valid'));

create table access_token (
	id serial primary key,
	account integer not null references account,
	token text not null,
	address inet not null,
	created timestamp default (now() at time zone 'utc'),
        expires timestamp default (now() at time zone 'utc' + '3 days'::interval)
);
create index access_token_token on access_token (token);

create table data (
	id serial primary key,
	name text not null unique,
	count integer not null default 0
);

insert into data (name) values ('default');
