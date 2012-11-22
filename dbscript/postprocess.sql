CREATE OR REPLACE FUNCTION last_func()
  RETURNS void AS
$BODY$
BEGIN
  delete from x_handout_details where hd_term_sn not in
    (select term_sn from x_terms);

/*1,2,4*/
DELETE
FROM
	x_handout_details
WHERE
	(hd_no, hd_term_sn)IN(
		SELECT
			hd_no,
			hd_term_sn
		FROM
			x_handout_details l_hd
		INNER JOIN x_handleout_data l_hx ON l_hd.hd_no = l_hx.ho_no
		WHERE
			l_hx.ho_server_kind IN('1', '2', '4')
		AND(
			l_hd.hd_term_sn,
			l_hd.hd_term_path,
			l_hx.ho_when
		)NOT IN(
			SELECT
				x_l_hd.hd_term_sn,
				x_l_hd.hd_term_path,
				MAX(x_l_hx.ho_when)
			FROM
				x_handleout_data x_l_hx
			INNER JOIN x_handout_details x_l_hd ON x_l_hd.hd_no = x_l_hx.ho_no
			WHERE
				x_l_hx.ho_server_kind IN('1', '2', '4')
			GROUP BY
				x_l_hd.hd_term_sn,
				x_l_hd.hd_term_path
		)
	);

/* 3,5,6 */
DELETE
FROM
	x_handout_details
WHERE
	(hd_no, hd_term_sn)IN(
		SELECT
			hd_no,
			hd_term_sn
		FROM
			x_handout_details l_hd
		INNER JOIN x_handleout_data l_hx ON l_hd.hd_no = l_hx.ho_no
		WHERE
			l_hx.ho_server_kind IN('3', '5', '6')
		AND(
			l_hd.hd_term_sn,
			COALESCE(l_hx.ho_term_file, l_hx.ho_server_file),
			l_hx.ho_when
		)NOT IN(
			SELECT
				x_l_hd.hd_term_sn,
				COALESCE(x_l_hx.ho_term_file, x_l_hx.ho_server_file),
				MAX(x_l_hx.ho_when)
			FROM
				x_handleout_data x_l_hx
			INNER JOIN x_handout_details x_l_hd ON x_l_hd.hd_no = x_l_hx.ho_no
			WHERE
				x_l_hx.ho_server_kind IN('3', '5', '6')
			GROUP BY
				x_l_hd.hd_term_sn,
				COALESCE(x_l_hx.ho_term_file, x_l_hx.ho_server_file)
		)
	);

/* 7, 9 */
DELETE
FROM
	x_handout_details
WHERE
	(hd_no, hd_term_sn)IN(
		SELECT
			hd_no,
			hd_term_sn
		FROM
			x_handout_details l_hd
		INNER JOIN x_handleout_data l_hx ON l_hd.hd_no = l_hx.ho_no
		WHERE
			l_hx.ho_server_kind IN('7', '9')
		AND(
			l_hd.hd_term_sn,
			COALESCE(l_hx.ho_term_file, l_hx.ho_server_file),
			l_hx.ho_when
		)NOT IN(
			SELECT
				x_l_hd.hd_term_sn,
				COALESCE(x_l_hx.ho_term_file, x_l_hx.ho_server_file),
				MAX(x_l_hx.ho_when)
			FROM
				x_handleout_data x_l_hx
			INNER JOIN x_handout_details x_l_hd ON x_l_hd.hd_no = x_l_hx.ho_no
			WHERE
				x_l_hx.ho_server_kind IN('7', '9')
			GROUP BY
				x_l_hd.hd_term_sn,
				COALESCE(x_l_hx.ho_term_file, x_l_hx.ho_server_file)
		)
	);

/* 0, framework */
DELETE
FROM
	x_handout_details
WHERE
	(hd_no, hd_term_sn)IN(
		SELECT
			hd_no,
			hd_term_sn
		FROM
			x_handout_details l_hd
		INNER JOIN x_handleout_data l_hx ON l_hd.hd_no = l_hx.ho_no
		WHERE
			l_hx.ho_server_kind = '0'
		AND(
			l_hd.hd_term_sn,
			l_hx.ho_when
		)NOT IN(
			SELECT
				x_l_hd.hd_term_sn,
				MAX(x_l_hx.ho_when)
			FROM
				x_handleout_data x_l_hx
			INNER JOIN x_handout_details x_l_hd ON x_l_hd.hd_no = x_l_hx.ho_no
			WHERE
				x_l_hx.ho_server_kind = '0'
			GROUP BY
				x_l_hd.hd_term_sn
		)
	);

/* 8 */
DELETE
FROM
	x_handout_details
WHERE
	(hd_no, hd_term_sn)IN(
		SELECT
			hd_no,
			hd_term_sn
		FROM
			x_handout_details l_hd
		INNER JOIN x_handleout_data l_hx ON l_hd.hd_no = l_hx.ho_no
		WHERE
			l_hx.ho_server_kind IN('8')
		AND(
			l_hd.hd_term_sn,
			COALESCE(l_hx.ho_term_file, l_hx.ho_server_file),
			l_hx.ho_when
		)NOT IN(
			SELECT
				x_l_hd.hd_term_sn,
				COALESCE(x_l_hx.ho_term_file, x_l_hx.ho_server_file),
				MAX(x_l_hx.ho_when)
			FROM
				x_handleout_data x_l_hx
			INNER JOIN x_handout_details x_l_hd ON x_l_hd.hd_no = x_l_hx.ho_no
			WHERE
				x_l_hx.ho_server_kind IN('8')
			GROUP BY
				x_l_hd.hd_term_sn,
				COALESCE(x_l_hx.ho_term_file, x_l_hx.ho_server_file)
		)
	);

  delete from x_handleout_data where (('now'::text)::timestamp(0) without time zone - ho_when > '60 Day');
END;
$BODY$
  LANGUAGE plpgsql VOLATILE
  COST 100;
ALTER FUNCTION last_func()
  OWNER TO postgres;

