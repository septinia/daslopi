This miner is forked from ore-hq-miner

To connect , download the miner and run
ore-hq-client --url ws://ore.tw-pool.com:5487/mine mine --username SOLANA_ADDRESS.WORKER_NAME --cores 32

To see your status , copy the following address and replace SOLANA_ADDRESS with your actual wallet

https://www2.tw-pool.com/workers/SOLANA_ADDRESS

To mine on hive:
download the latest hiveos miner file and add custom miner , put the following line in the "Extra config  arguments"
--url ws://ore.tw-pool.com:5487/mine mine --username %WAL%.%WORKER_NAME% --cores 32


使用方式:
下載對應的ubuntu版本,然後執行
ore-hq-client --url ws://ore.tw-pool.com:5487/mine mine --username 錢包地址.機器名稱 --cores 32

在網頁上看狀態: https://www.tw-pool.com/workers/錢包地址

hive:
下載最新版的hive miner
在"Extra config  arguments" 填入
--url ws://ore.tw-pool.com:5487/mine mine --username %WAL%.%WORKER_NAME% --cores 32
