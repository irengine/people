/*
CREATE TABLE tb_clients
(
  client_id character varying(31) NOT NULL,
  auto_seq serial NOT NULL,
  client_expired boolean NOT NULL DEFAULT false,
  client_password character varying(23),
  client_change_passwd boolean NOT NULL DEFAULT false,
  CONSTRAINT pk_tb_clients PRIMARY KEY (client_id )
)
CREATE INDEX idx_client_seq
  ON tb_clients
  USING btree
  (auto_seq );
*/


CREATE TABLE x_terms
(
  term_sn character varying(31) NOT NULL,
  term_serial serial NOT NULL,
  term_bad boolean NOT NULL DEFAULT false,
  term_key character varying(23),
  term_set_key boolean NOT NULL DEFAULT false,
  CONSTRAINT pk_x_terms PRIMARY KEY (term_sn )
)
WITH (
  OIDS=FALSE
);
ALTER TABLE x_terms
  OWNER TO postgres;


CREATE INDEX idx_terms_serial
  ON x_terms
  USING btree
  (term_serial );
  

/*
CREATE TABLE tb_config
(
  cfg_id integer NOT NULL,
  cfg_value character varying(200) NOT NULL,
  CONSTRAINT tb_config_pkey PRIMARY KEY (cfg_id )
)*/
  
CREATE TABLE x_sinfo
(
  skey integer NOT NULL,
  sdata character varying(200) NOT NULL,
  CONSTRAINT x_sinfo_pkey PRIMARY KEY (skey )
)
WITH (
  OIDS=FALSE
);
ALTER TABLE x_sinfo
  OWNER TO postgres;

/*
CREATE TABLE tb_dist_info
(
  dist_id character varying(32) NOT NULL,
  dist_type character(1) NOT NULL,
  dist_aindex character varying(256),
  dist_findex character varying(256),
  dist_fdir character varying(1024),
  dist_ftype character(1) NOT NULL,
  dist_time timestamp without time zone NOT NULL DEFAULT ('now'::text)::timestamp(0) without time zone,
  dist_password character varying(16) NOT NULL,
  dist_md5 text,
  dist_mbz_md5 character varying(32),
  CONSTRAINT pk_dist_info PRIMARY KEY (dist_id ),
  CONSTRAINT tb_dist_info_dist_ftype_check CHECK (dist_ftype = ANY (ARRAY['0'::bpchar, '1'::bpchar, '2'::bpchar, '3'::bpchar, '4'::bpchar, '5'::bpchar, '6'::bpchar, '7'::bpchar, '8'::bpchar, '9'::bpchar])),
  CONSTRAINT tb_dist_info_dist_type_check CHECK (dist_type = ANY (ARRAY['0'::bpchar, '1'::bpchar, '3'::bpchar]))
)
*/

CREATE TABLE x_handleout_data
(
  ho_no character varying(32) NOT NULL,
  ho_kind character(1) NOT NULL,
  ho_term_file character varying(256),
  ho_server_file character varying(256),
  ho_server_path character varying(1024),
  ho_server_kind character(1) NOT NULL,
  ho_when timestamp without time zone NOT NULL DEFAULT ('now'::text)::timestamp(0) without time zone,
  ho_key character varying(16) NOT NULL,
  ho_checksum text,
  ho_zip_checksum character varying(32),
  CONSTRAINT pk_handleout_data PRIMARY KEY (ho_no ),
  CONSTRAINT x_handleout_data_server_kind_check CHECK (ho_server_kind = ANY (ARRAY['0'::bpchar, '1'::bpchar, '2'::bpchar, '3'::bpchar, '4'::bpchar, '5'::bpchar, '6'::bpchar, '7'::bpchar, '8'::bpchar, '9'::bpchar])),
  CONSTRAINT x_handleout_data_kind_check CHECK (ho_kind = ANY (ARRAY['0'::bpchar, '1'::bpchar, '3'::bpchar]))
)
WITH (
  OIDS=FALSE
);
ALTER TABLE x_handleout_data
  OWNER TO postgres;

/*  
CREATE TABLE tb_dist_clients
(
  dc_dist_id character varying(32) NOT NULL,
  dc_client_id character varying(24) NOT NULL,
  dc_status integer NOT NULL DEFAULT 0,
  dc_adir character varying(256),
  dc_last_update timestamp without time zone NOT NULL DEFAULT ('now'::text)::timestamp(0) without time zone,
  dc_md5 text,
  dc_mbz_file character varying(1024),
  dc_mbz_md5 character varying(32),
  CONSTRAINT pk_dist_clients PRIMARY KEY (dc_dist_id , dc_client_id ),
  CONSTRAINT tb_dist_clients_dc_dist_id_fkey FOREIGN KEY (dc_dist_id)
      REFERENCES tb_dist_info (dist_id) MATCH SIMPLE
      ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT tb_dist_clients_dc_status_check CHECK (dc_status >= 0 AND dc_status <= 8)
)

CREATE INDEX idx_dist_clients
  ON tb_dist_clients
  USING btree
  (dc_client_id COLLATE pg_catalog."default" );
*/

CREATE TABLE x_handout_details
(
  hd_no character varying(32) NOT NULL,
  hd_term_sn character varying(24) NOT NULL,
  hd_state integer NOT NULL DEFAULT 0,
  hd_term_path character varying(256),
  hd_prev_access timestamp without time zone NOT NULL DEFAULT ('now'::text)::timestamp(0) without time zone,
  hd_checksum text,
  hd_zip_name character varying(1024),
  hd_zip_checksum character varying(32),
  CONSTRAINT pk_handout_details PRIMARY KEY (hd_no , hd_term_sn ),
  CONSTRAINT handout_details_fkey FOREIGN KEY (hd_no)
      REFERENCES x_handleout_data (ho_no) MATCH SIMPLE
      ON UPDATE CASCADE ON DELETE CASCADE,
  CONSTRAINT x_handout_details_hd_state_check CHECK (hd_state >= 0 AND hd_state <= 8)
)
WITH (
  OIDS=FALSE
);
ALTER TABLE x_handout_details
  OWNER TO postgres;

CREATE INDEX idx_handout_details
  ON x_handout_details
  USING btree
  (hd_term_sn COLLATE pg_catalog."default" );

insert into x_sinfo(skey, sdata) values(1, '1');
insert into x_sinfo(skey, sdata) values(2, '9;8;2;3;4;5;6;7;0;1');
