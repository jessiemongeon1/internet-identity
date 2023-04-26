WITH
    1 AS DAYS_INTERVAL,
    'rdmx6-jaaaa-aaaaa-aaadq-cai' AS CANISTER_ID,
    'https://identity.ic0.app' AS ORIGIN,
    ('prepare_delegation', 'get_anchor_info', 'register') AS RELEVANT_ACTION,
    page_load_ips as
    (
    SELECT remote_addr_hashed
    FROM http_access_distributed
    WHERE date > addDays(now(), -1 * DAYS_INTERVAL)
    AND ic_canister_id == CANISTER_ID
    AND http_origin == ORIGIN
    AND ic_method_name == 'http_request'
    ),
    action_ips as
    (
    SELECT remote_addr_hashed
    FROM http_access_distributed
    WHERE date > addDays(now(), -1 * DAYS_INTERVAL)
    AND ic_canister_id == CANISTER_ID
    AND http_origin == ORIGIN
    AND ic_method_name IN RELEVANT_ACTION
    )
SELECT
(
    (
        -- the number of unique IPs that performed a page load but no relevant action
        SELECT count(DISTINCT remote_addr_hashed)
        FROM page_load_ips
        LEFT JOIN action_ips ON page_load_ips.remote_addr_hashed == action_ips.remote_addr_hashed
        WHERE action_ips.remote_addr_hashed == '')
    - (
        -- the number of unique IPs that performed a relevant action but no page load (these presumably exist due to sampling missing the page load)
        SELECT count(DISTINCT remote_addr_hashed)
        FROM action_ips
        LEFT JOIN page_load_ips ON action_ips.remote_addr_hashed == page_load_ips.remote_addr_hashed
        WHERE page_load_ips.remote_addr_hashed == '')
    )
    / (
            (
            -- the number of unique IPs that performed a page load
            SELECT count(DISTINCT remote_addr_hashed)
            FROM page_load_ips)
        + (
            -- the number of unique IPs that performed a relevant action but no page load (these presumably exist due to sampling missing the page load)
            SELECT count(DISTINCT remote_addr_hashed)
            FROM action_ips
            LEFT JOIN page_load_ips ON action_ips.remote_addr_hashed == page_load_ips.remote_addr_hashed
            WHERE page_load_ips.remote_addr_hashed == '')
) AS bounce_rate;