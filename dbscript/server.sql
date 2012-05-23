CREATE or replace FUNCTION post_process() RETURNS void AS 
$$
BEGIN
  delete from tb_dist_clients where dc_client_id not in
    (select client_id from tb_clients);

	delete from tb_dist_clients where (dc_dist_id, dc_client_id) in
	(
		select dc_dist_id, dc_client_id from tb_dist_clients dc, tb_dist_info di
		  where dc.dc_dist_id = di.dist_id and di.dist_ftype in ('1', '2', '4') and di.dist_time < 
		    (select max(x_di.dist_time) from tb_dist_info x_di, tb_dist_clients x_dc 
		      where x_dc.dc_dist_id = x_di.dist_id and x_dc.dc_adir = dc.dc_adir 
		            and x_di.dist_ftype in ('1', '2', '4')
		    )
	);

  delete from tb_dist_clients where (dc_dist_id, dc_client_id) in
	(
		select dc_dist_id, dc_client_id from tb_dist_clients dc, tb_dist_info di
		  where dc.dc_dist_id = di.dist_id and di.dist_ftype in ('3', '5', '6') and di.dist_time < 
		    (select max(x_di.dist_time) from tb_dist_info x_di, tb_dist_clients x_dc 
		      where x_dc.dc_dist_id = x_di.dist_id and COALESCE(x_di.dist_aindex, x_di.dist_findex) = COALESCE(di.dist_aindex, di.dist_findex)
		            and x_di.dist_ftype in ('3', '5', '6')
		    )
	);

	delete from tb_dist_clients where (dc_dist_id, dc_client_id) in
	(
		select dc_dist_id, dc_client_id from tb_dist_clients dc, tb_dist_info di
		  where dc.dc_dist_id = di.dist_id and di.dist_ftype in ('7', '9') and di.dist_time < 
		    (select max(x_di.dist_time) from tb_dist_info x_di, tb_dist_clients x_dc 
		      where x_dc.dc_dist_id = x_di.dist_id and COALESCE(x_di.dist_aindex, x_di.dist_findex) = COALESCE(di.dist_aindex, di.dist_findex)
		            and x_di.dist_ftype in ('7', '9')
		    )
	);

	delete from tb_dist_clients where (dc_dist_id, dc_client_id) in
	(
		select dc_dist_id, dc_client_id from tb_dist_clients dc, tb_dist_info di
		  where dc.dc_dist_id = di.dist_id and di.dist_ftype = '0' and di.dist_time < 
		    (select max(x_di.dist_time) from tb_dist_info x_di, tb_dist_clients x_dc 
		      where x_dc.dc_dist_id = x_di.dist_id and x_di.dist_ftype = '0'
		    )
	);

	delete from tb_dist_clients where (dc_dist_id, dc_client_id) in
	(
		select dc_dist_id, dc_client_id from tb_dist_clients dc, tb_dist_info di
		  where dc.dc_dist_id = di.dist_id and di.dist_ftype = '8' and di.dist_time < 
		    (select max(x_di.dist_time) from tb_dist_info x_di, tb_dist_clients x_dc 
		      where x_dc.dc_dist_id = x_di.dist_id and COALESCE(x_di.dist_aindex, x_di.dist_findex) = COALESCE(di.dist_aindex, di.dist_findex)
		            and x_di.dist_ftype = '8'
		    )
	);

--  delete from tb_dist_info where (('now'::text)::timestamp(0) without time zone - dist_time > '5 day') and (dist_id not in 
--    (select distinct dc_dist_id from tb_dist_clients));

  delete from tb_dist_info where (('now'::text)::timestamp(0) without time zone - dist_time > '60 day');
END;
$$ 
LANGUAGE plpgsql;

ALTER TABLE tb_dist_clients
  drop CONSTRAINT tb_dist_clients_dc_status_check;
ALTER TABLE tb_dist_clients
  ADD CONSTRAINT tb_dist_clients_dc_status_check CHECK (dc_status >= 0 AND dc_status <= 8);
insert into tb_config(cfg_id, cfg_value) values(2, '');  
