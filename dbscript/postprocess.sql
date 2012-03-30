CREATE or replace FUNCTION post_process() RETURNS void AS 
$$
BEGIN
  delete from tb_dist_clients where dc_client_id not in
    (select client_id from tb_clients);

/* 1,2,4 */
/*
delete from tb_dist_clients where (dc_dist_id, dc_client_id) in
(
select dc_dist_id, dc_client_id from tb_dist_clients dc, tb_dist_info di
  where dc.dc_dist_id = di.dist_id and di.dist_ftype in ('1', '2', '4') and di.dist_time < 
    (select max(x_di.dist_time) from tb_dist_info x_di, tb_dist_clients x_dc 
      where x_dc.dc_dist_id = x_di.dist_id and x_dc.dc_adir = dc.dc_adir 
            and x_di.dist_ftype in ('1', '2', '4')
    )
);*/
DELETE
FROM
	tb_dist_clients
WHERE
	(dc_dist_id, dc_client_id)IN(
		SELECT
			dc_dist_id,
			dc_client_id
		FROM
			tb_dist_clients dc
		INNER JOIN tb_dist_info di ON dc.dc_dist_id = di.dist_id
		WHERE
			di.dist_ftype IN('1', '2', '4')
		AND(
			dc.dc_client_id,
			dc.dc_adir,
			di.dist_time
		)NOT IN(
			SELECT
				x_dc.dc_client_id,
				x_dc.dc_adir,
				MAX(x_di.dist_time)
			FROM
				tb_dist_info x_di
			INNER JOIN tb_dist_clients x_dc ON x_dc.dc_dist_id = x_di.dist_id
			WHERE
				x_di.dist_ftype IN('1', '2', '4')
			GROUP BY
				x_dc.dc_client_id,
				x_dc.dc_adir
		)
	);

/* 3,5,6 */
/*
  delete from tb_dist_clients where (dc_dist_id, dc_client_id) in
(
select dc_dist_id, dc_client_id from tb_dist_clients dc, tb_dist_info di
  where dc.dc_dist_id = di.dist_id and di.dist_ftype in ('3', '5', '6') and di.dist_time < 
    (select max(x_di.dist_time) from tb_dist_info x_di, tb_dist_clients x_dc 
      where x_dc.dc_dist_id = x_di.dist_id and COALESCE(x_di.dist_aindex, x_di.dist_findex) = COALESCE(di.dist_aindex, di.dist_findex)
            and x_di.dist_ftype in ('3', '5', '6')
    )
);*/
DELETE
FROM
	tb_dist_clients
WHERE
	(dc_dist_id, dc_client_id)IN(
		SELECT
			dc_dist_id,
			dc_client_id
		FROM
			tb_dist_clients dc
		INNER JOIN tb_dist_info di ON dc.dc_dist_id = di.dist_id
		WHERE
			di.dist_ftype IN('3', '5', '6')
		AND(
			dc.dc_client_id,
			COALESCE(di.dist_aindex, di.dist_findex),
			di.dist_time
		)NOT IN(
			SELECT
				x_dc.dc_client_id,
				COALESCE(x_di.dist_aindex, x_di.dist_findex),
				MAX(x_di.dist_time)
			FROM
				tb_dist_info x_di
			INNER JOIN tb_dist_clients x_dc ON x_dc.dc_dist_id = x_di.dist_id
			WHERE
				x_di.dist_ftype IN('3', '5', '6')
			GROUP BY
				x_dc.dc_client_id,
				COALESCE(x_di.dist_aindex, x_di.dist_findex)
		)
	);

/* 7, 9 */
/*
delete from tb_dist_clients where (dc_dist_id, dc_client_id) in
(
select dc_dist_id, dc_client_id from tb_dist_clients dc, tb_dist_info di
  where dc.dc_dist_id = di.dist_id and di.dist_ftype in ('7', '9') and di.dist_time < 
    (select max(x_di.dist_time) from tb_dist_info x_di, tb_dist_clients x_dc 
      where x_dc.dc_dist_id = x_di.dist_id and COALESCE(x_di.dist_aindex, x_di.dist_findex) = COALESCE(di.dist_aindex, di.dist_findex)
            and x_di.dist_ftype in ('7', '9')
    )
);*/
DELETE
FROM
	tb_dist_clients
WHERE
	(dc_dist_id, dc_client_id)IN(
		SELECT
			dc_dist_id,
			dc_client_id
		FROM
			tb_dist_clients dc
		INNER JOIN tb_dist_info di ON dc.dc_dist_id = di.dist_id
		WHERE
			di.dist_ftype IN('7', '9')
		AND(
			dc.dc_client_id,
			COALESCE(di.dist_aindex, di.dist_findex),
			di.dist_time
		)NOT IN(
			SELECT
				x_dc.dc_client_id,
				COALESCE(x_di.dist_aindex, x_di.dist_findex),
				MAX(x_di.dist_time)
			FROM
				tb_dist_info x_di
			INNER JOIN tb_dist_clients x_dc ON x_dc.dc_dist_id = x_di.dist_id
			WHERE
				x_di.dist_ftype IN('7', '9')
			GROUP BY
				x_dc.dc_client_id,
				COALESCE(x_di.dist_aindex, x_di.dist_findex)
		)
	);

/* 0, framework */
DELETE
FROM
	tb_dist_clients
WHERE
	(dc_dist_id, dc_client_id)IN(
		SELECT
			dc_dist_id,
			dc_client_id
		FROM
			tb_dist_clients dc
		INNER JOIN tb_dist_info di ON dc.dc_dist_id = di.dist_id
		WHERE
			di.dist_ftype = '0'
		AND(
			dc.dc_client_id,
			di.dist_time
		)NOT IN(
			SELECT
				x_dc.dc_client_id,
				MAX(x_di.dist_time)
			FROM
				tb_dist_info x_di
			INNER JOIN tb_dist_clients x_dc ON x_dc.dc_dist_id = x_di.dist_id
			WHERE
				x_di.dist_ftype = '0'
			GROUP BY
				x_dc.dc_client_id
		)
	);

/* 8 */
/*
delete from tb_dist_clients where (dc_dist_id, dc_client_id) in
(
select dc_dist_id, dc_client_id from tb_dist_clients dc, tb_dist_info di
  where dc.dc_dist_id = di.dist_id and di.dist_ftype = '8' and di.dist_time < 
    (select max(x_di.dist_time) from tb_dist_info x_di, tb_dist_clients x_dc 
      where x_dc.dc_dist_id = x_di.dist_id and COALESCE(x_di.dist_aindex, x_di.dist_findex) = COALESCE(di.dist_aindex, di.dist_findex)
            and x_di.dist_ftype = '8'
    )
);*/
DELETE
FROM
	tb_dist_clients
WHERE
	(dc_dist_id, dc_client_id)IN(
		SELECT
			dc_dist_id,
			dc_client_id
		FROM
			tb_dist_clients dc
		INNER JOIN tb_dist_info di ON dc.dc_dist_id = di.dist_id
		WHERE
			di.dist_ftype IN('8')
		AND(
			dc.dc_client_id,
			COALESCE(di.dist_aindex, di.dist_findex),
			di.dist_time
		)NOT IN(
			SELECT
				x_dc.dc_client_id,
				COALESCE(x_di.dist_aindex, x_di.dist_findex),
				MAX(x_di.dist_time)
			FROM
				tb_dist_info x_di
			INNER JOIN tb_dist_clients x_dc ON x_dc.dc_dist_id = x_di.dist_id
			WHERE
				x_di.dist_ftype IN('8')
			GROUP BY
				x_dc.dc_client_id,
				COALESCE(x_di.dist_aindex, x_di.dist_findex)
		)
	);

  delete from tb_dist_info where (('now'::text)::timestamp(0) without time zone - dist_time > '60 day');
END;
$$ 
LANGUAGE plpgsql;

