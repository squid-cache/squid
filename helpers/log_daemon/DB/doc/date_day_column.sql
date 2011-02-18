-- we need a separate column to store the date and time of the request
ALTER TABLE access_log ADD COLUMN date_day DATE;
ALTER TABLE access_log ADD COLUMN date_time TIME;

-- let's populate the new columns, in case some rows already exist;
-- the date and time values should be set by a trigger
UPDATE access_log SET date_day  = DATE(FROM_UNIXTIME(time_since_epoch));
UPDATE access_log SET date_time = TIME(FROM_UNIXTIME(time_since_epoch));

-- let's create a view that uses the date column
CREATE VIEW requests_per_day_2 AS SELECT date_day, COUNT(*) AS num_of_requests FROM access_log GROUP BY 1 ORDER BY 1;

-- that view needs an index on the group by column
CREATE INDEX date_day_idx ON access_log(date_day);


-- a trigger that automatically extracts the date value from the time_since_epoch column
-- and stores it in the date_day column
DELIMITER //
CREATE TRIGGER extract_date_day_bi BEFORE INSERT ON access_log FOR EACH ROW
BEGIN
	SET NEW.date_day  = DATE(FROM_UNIXTIME(NEW.time_since_epoch));
    SET NEW.date_time = TIME(FROM_UNIXTIME(NEW.time_since_epoch));
END //


-- Note: after running this script against an already populated access_log,
-- views have to be recreated, or the new date_day column will not show up.
