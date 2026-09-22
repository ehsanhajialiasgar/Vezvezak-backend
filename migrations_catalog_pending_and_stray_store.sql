-- TWO PRODUCTION CORRECTIONS FROM THE SELLER WALKTHROUGH (Ehsan 2026-09-22). Safe to run twice.
--
-- 1. The CSV bulk-upload path wrote status='pending' while the single-item path wrote 'live'. There is no
--    reviewer and no batch review, so those rows were invisible to every buyer for ever, while the app said
--    "Uploaded 3 item(s)" and the seller's own list counted them. The code is fixed (catalogBulk now writes
--    'live', refusable only by the deterministic prohibited screen); these are the rows already stranded.
--    Nothing here can promote a row the screen REFUSED: 'rejected' is untouched.
UPDATE catalog_items SET status = 'live', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
 WHERE status = 'pending';

-- 2. An empty duplicate store named "Moozoonf" owned by test2@vez.test. It exists because a reinstall did not
--    sign the previous account out (the Keychain outlives the app container), so the seller wizard was completed
--    under the wrong account. It holds no catalogue items and no variants — checked before writing this — so the
--    delete orphans nothing. The real Moozoonf store (mch_bkw8s3L-MLOdOiYg, owner moozoonf@vez.test) is untouched.
DELETE FROM merchants
 WHERE id = 'mch_-7_R6sQEuJuh5aaC'
   AND store_name = 'Moozoonf'
   AND user_id = (SELECT id FROM users WHERE identifier = 'test2@vez.test')
   AND NOT EXISTS (SELECT 1 FROM catalog_items WHERE merchant_id = 'mch_-7_R6sQEuJuh5aaC');
