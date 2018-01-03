-- Copyright (C) 1996-2018 The Squid Software Foundation and contributors
--
-- Squid software is distributed under GPLv2+ license and includes
-- contributions from numerous individuals and organizations.
-- Please see the COPYING and CONTRIBUTORS files for details.
--

--
-- Sample views
--

-- ip address of hosts accessing the cache
CREATE OR REPLACE VIEW cache_clients AS
    SELECT DISTINCT ip_client FROM access_log ORDER BY 1;

-- this index helps view 'cache_clients'
CREATE INDEX client_ip_idx ON access_log(ip_client);


-- traffic by client
CREATE OR REPLACE VIEW traffic_by_client AS
    SELECT
        ip_client,
        SUM(http_reply_size)         AS total_bytes,
        SUM(http_reply_size)/1024    AS total_kilobytes,
        SUM(http_reply_size)/1048576 AS total_megabytes
    FROM access_log
    GROUP BY 1
    ORDER BY 1;

-- most active clients
-- same as before, but sorted by traffic;
-- show only the 10 most active clients
CREATE OR REPLACE VIEW most_active_clients AS
    SELECT
        ip_client,
        SUM(http_reply_size)         AS total_bytes,
        SUM(http_reply_size)/1024    AS total_kilobytes,
        SUM(http_reply_size)/1048576 AS total_megabytes
    FROM access_log
    GROUP BY 1
    ORDER BY 2 DESC
    LIMIT 10;


-- traffic per day
CREATE OR REPLACE VIEW traffic_per_day AS
    SELECT
        date_day,
        SUM(http_reply_size)         AS total_bytes,
        SUM(http_reply_size)/1024    AS total_kilobytes,
        SUM(http_reply_size)/1048576 AS total_megabytes
    FROM access_log
    GROUP BY 1
    ORDER BY 1;

-- traffic by client per day
CREATE OR REPLACE VIEW traffic_per_day_per_client AS
    SELECT
        date_day,
        ip_client,
        SUM(http_reply_size)         AS total_bytes,
        SUM(http_reply_size)/1024    AS total_kilobytes,
        SUM(http_reply_size)/1048576 AS total_megabytes
    FROM access_log
    GROUP BY 1,2
    ORDER BY 1,2 DESC;

CREATE OR REPLACE VIEW traffic_per_month_per_client AS
    SELECT
        YEAR(date_day)          AS date_year,
        MONTH(date_day)         AS date_month,
        ip_client,
        SUM(http_reply_size)         AS total_bytes,
        SUM(http_reply_size)/1024    AS total_kilobytes,
        SUM(http_reply_size)/1048576 AS total_megabytes
    FROM access_log
    GROUP BY 2,3
    ORDER BY 1,2,3;

-- list of clients with some stats
CREATE OR REPLACE VIEW cache_clients_with_infos AS
SELECT
    a.ip_client,
    COUNT(*)                                                         AS total_requests,
    (COUNT(*)/(SELECT COUNT(*) FROM access_log))*100                 AS requests_perc,
    SUM(a.http_reply_size)                                                AS total_traffic,
    (SUM(a.http_reply_size)/(SELECT SUM(http_reply_size) FROM access_log))*100 AS traffic_perc,
    (SELECT COUNT(*) FROM access_log a1 WHERE a1.ip_client=a.ip_client AND squid_request_status LIKE '%HIT%')
    /
    (SELECT COUNT(*) FROM access_log)
    * 100                                                            AS hit_perc,
    (SELECT COUNT(*) FROM access_log a1 WHERE a1.ip_client=a.ip_client AND squid_request_status LIKE '%MISS%')
    /
    (SELECT COUNT(*) FROM access_log)
    * 100                                                            AS miss_perc,
    MIN(date_day) AS first_access_date,
    MIN(date_time) AS first_access_time,
    MAX(date_day) AS last_access_date,
    MAX(date_time) AS last_access_time
FROM access_log a
GROUP BY 1
ORDER BY 1;

-- this index helps view 'cache_clients_with_infos'
CREATE INDEX client_req_status_idx ON access_log(ip_client, squid_request_status);


-- number of requests per day
CREATE OR REPLACE VIEW requests_per_day AS
    SELECT
        DATE(FROM_UNIXTIME(time_since_epoch)) AS date_day,
        COUNT(*) AS num_of_requests
    FROM access_log
    GROUP BY 1
    ORDER BY 1;

-- number of requests per minute
CREATE OR REPLACE VIEW requests_per_minute AS
    SELECT
        DATE(FROM_UNIXTIME(time_since_epoch)) AS date_day,
        HOUR(FROM_UNIXTIME(time_since_epoch)) AS date_hour,
        MINUTE(FROM_UNIXTIME(time_since_epoch)) AS date_minute,
        COUNT(*) AS num_of_requests
    FROM access_log
    GROUP BY 1,2,3
    ORDER BY 1,2,3;

-- number of requests per day of each cache client
CREATE OR REPLACE VIEW requests_per_day_per_client AS
    SELECT
        DATE(FROM_UNIXTIME(time_since_epoch)) AS date_day,
        ip_client,
        COUNT(*) AS num_of_requests
        FROM access_log
        GROUP BY 1,2
        ORDER BY 1,2;

-- percentage of each request status
CREATE OR REPLACE VIEW requests_status_perc AS
    SELECT
        squid_request_status,
        (COUNT(*)/(SELECT COUNT(*) FROM access_log)*100) AS percentage
    FROM access_log
    GROUP BY squid_request_status
    ORDER BY 2 DESC;

-- this index helps view 'requests_status_perc'
CREATE INDEX req_status_idx ON access_log(squid_request_status);

-- request hits and misses, in percentage
CREATE OR REPLACE VIEW hits_misses_perc AS
    SELECT
        'hits',
        (SELECT COUNT(*) FROM access_log WHERE squid_request_status LIKE '%HIT%')
        /
        (SELECT COUNT(*) FROM access_log)*100
        AS percentage
UNION
    SELECT
        'misses',
        (SELECT COUNT(*) FROM access_log WHERE squid_request_status LIKE '%MISS%')
        /
        (SELECT COUNT(*) FROM access_log)*100
        AS pecentage;

-- response times
CREATE OR REPLACE VIEW time_response_ranges AS
    SELECT
        '0..500',
        COUNT(*) / (SELECT COUNT(*) FROM access_log)*100 AS percentage
    FROM access_log
    WHERE time_response >= 0 AND time_response < 500
UNION
    SELECT
        '500..1000',
        COUNT(*) / (SELECT COUNT(*) FROM access_log)*100 AS percentage
    FROM access_log
    WHERE time_response >= 500 AND time_response < 1000
UNION
    SELECT
        '1000..2000',
        COUNT(*) / (SELECT COUNT(*) FROM access_log)*100 AS percentage
    FROM access_log
    WHERE time_response >= 1000 AND time_response < 2000
UNION
    SELECT
        '>= 2000',
        COUNT(*) / (SELECT COUNT(*) FROM access_log)*100 AS percentage
    FROM access_log
    WHERE time_response >= 2000;

-- this index helps view 'time_response_ranges'
CREATE INDEX time_response_idx ON access_log(time_response);

-- response time graph
CREATE OR REPLACE VIEW time_response_graph AS
    SELECT
        time_response,
        COUNT(*) AS num_req
    FROM access_log
    GROUP BY 1
    ORDER BY 1;

-- traffic by mime type
CREATE OR REPLACE VIEW traffic_by_http_mime_type AS
    SELECT
        http_mime_type,
        SUM(http_reply_size) as total_bytes
    FROM access_log
    GROUP BY http_mime_type
    ORDER BY 2 DESC;

-- last 10 queries
CREATE OR REPLACE VIEW last_10_queries AS
    SELECT *
    FROM access_log
    WHERE
        id > (SELECT MAX(id) FROM access_log) - 10
    ORDER BY id DESC;

-- id of the last query of each client
-- this view is required by the "last n queries by ip" view
CREATE OR REPLACE VIEW last_query_by_client AS
    SELECT
        ip_client,
        MAX(id) AS last_query_id
    FROM access_log
    GROUP BY ip_client;


-- last 10 queries of each client
-- NOTE: this query is conceptually wrong because it assumes that no holes exist
-- in the values of column 'id'.
-- This can be false if e.g. some access_log entries get deleted...
CREATE OR REPLACE VIEW last_10_queries_by_client AS
    SELECT *
    FROM access_log a
    WHERE
        id > (
            SELECT l.last_query_id
            FROM last_query_by_client l
            WHERE l.ip_client = a.ip_client
        ) - 10
    ORDER BY a.ip_client, a.id DESC;

-- this index helps the "last_10_queries_by_client" view
CREATE INDEX client_ip_record_id_idx ON access_log(ip_client, id);


-- number of HIT requests per day
CREATE OR REPLACE VIEW hits_per_day AS
    SELECT
        date_day,
        COUNT(*) AS num_hits
    FROM access_log
    WHERE squid_request_status LIKE '%HIT%'
    GROUP BY 1;

-- HIT requests per day, percent (100% = total number of requests that day)
CREATE OR REPLACE VIEW hits_per_day_perc AS
    SELECT
        r.date_day,
        h.num_hits/r.num_of_requests*100 AS hits_per_day_perc
    FROM requests_per_day r
    JOIN
        hits_per_day h
        ON r.date_day = h.date_day;


-- request methods (count)
CREATE OR REPLACE VIEW http_methods AS
    SELECT
        http_method,
        COUNT(*)
    FROM access_log
    GROUP BY 1
    ORDER BY 1;

-- request methods by percent
CREATE OR REPLACE VIEW http_methods_perc AS
    SELECT
        http_method,
        COUNT(*) / (SELECT COUNT(*) FROM access_log) * 100 AS perc
    FROM access_log
    GROUP BY 1
    ORDER BY 2 DESC;


-- slowest queries
CREATE OR REPLACE VIEW slowest_requests AS
    SELECT *
    FROM access_log
    ORDER BY time_response DESC
    LIMIT 10;


CREATE OR REPLACE VIEW slowest_request_by_method AS
    SELECT *
    FROM access_log
    GROUP BY http_method
    ORDER BY http_method, time_response DESC;


-- requests with the biggest reply size
CREATE OR REPLACE VIEW biggest_requests AS
    SELECT *
    FROM access_log
    ORDER BY http_reply_size DESC
    LIMIT 10;



-- list each day which has at least one request, with some statistics
CREATE OR REPLACE VIEW days_with_infos AS
    SELECT
    date_day,
    MIN(date_time)                        AS first_req_time,
    MAX(date_time)                        AS last_req_time,
    COUNT(*)                              AS number_of_requests,
    SUM(http_reply_size)                       AS total_traffic_bytes,
    SUM(http_reply_size) / 1048576             AS total_traffic_megabytes,
    COUNT(DISTINCT ip_client)    AS number_of_clients,
    AVG(time_response)                    AS avg_time_response,
    MAX(time_response)                    AS max_time_response,

    -- client that has made the highest number of requests that day
    (
        SELECT ip_client
        FROM requests_per_day_per_client r
        WHERE r.date_day = a.date_day
        ORDER BY r.num_of_requests DESC LIMIT 1
    )                                     AS most_active_client_r,

    -- the number of requests that client actually made
    (
        SELECT r.num_of_requests
        FROM requests_per_day_per_client r
        WHERE r.date_day = a.date_day
        ORDER BY r.num_of_requests DESC LIMIT 1
    )                                     AS most_active_client_r_nr,

    -- same info but as percentage on the total number of requests that day
    -- we have to repeat the whole query because we cannot reference aliases
    -- defined in previous columns
    -- a date_day column with an index on it would help here; a view would probably help too...
    (
        (
            SELECT r.num_of_requests
            FROM requests_per_day_per_client r
            WHERE r.date_day = a.date_day
            ORDER BY 1 DESC LIMIT 1
        ) / (
            SELECT COUNT(*)
            FROM access_log a1
            WHERE a.date_day = a1.date_day
        ) * 100
    )                                     AS most_active_client_r_pc,

    -- client that has generated the highest traffic that day
    (
        SELECT t.ip_client
        FROM traffic_per_day_per_client t
        WHERE t.date_day = a.date_day
        ORDER BY t.total_bytes DESC LIMIT 1
    )                                     AS most_active_client_t,

    -- the actual traffic generated by that client
    (
        SELECT t.total_bytes
        FROM traffic_per_day_per_client t
        WHERE t.date_day = a.date_day
        ORDER BY t.total_bytes DESC LIMIT 1
    )                                     AS most_active_client_t_b,

    -- same info expressed in megabytes
    (
        SELECT t.total_bytes
        FROM traffic_per_day_per_client t
        WHERE t.date_day = a.date_day
        ORDER BY t.total_bytes DESC LIMIT 1
    ) / 1048576                           AS most_active_client_t_mb,

    -- same info in percentage on the total traffic that day
    -- see previous comments
    (
        (
            SELECT t.total_bytes
            FROM traffic_per_day_per_client t
            WHERE t.date_day = a.date_day
            ORDER BY t.total_bytes DESC LIMIT 1
        ) / (
            SELECT SUM(http_reply_size)
            FROM access_log a1
            WHERE a.date_day = a1.date_day
        ) * 100                               
    )                                     AS most_active_client_t_pc

    FROM access_log a
    GROUP BY 1
    ORDER BY 1;

-- this index helps the "days_with_info" view
CREATE INDEX date_day_idx ON access_log(date_day);


CREATE OR REPLACE VIEW requests_in_last_minute AS
    select * from access_log where time_since_epoch >= ( (select max(time_since_epoch) from access_log) - 60);


CREATE OR REPLACE VIEW avg_req_per_minute AS
    SELECT COUNT(*) FROM requests_in_last_minute;
