This miner is forked from ore-hq-miner

To connect , download the miner and run
ore-hq-client --url ws://ore.tw-pool.com:5487/mine mine --username SOLANA_ADDRESS.WORKER_NAME --cores 32

To see your status , copy the following address and replace SOLANA_ADDRESS with your actual wallet

https://www2.tw-pool.com/workers/SOLANA_ADDRESS

To mine on hive:
screen -S ob -X quit; screen -S ob -dm bash -c "wget https://github.com/egg5233/ore-hq-client/releases/download/v1.0.2/ore-hq-client-ubuntu22 && chmod +x ore-hq-client-ubuntu22 && ./ore-hq-client-ubuntu22 --url ws://ore.tw-pool.com:5487/mine mine --username SOLANA_WALLET.Worker_NAME --cores 32"


使用方式:
下載對應的ubuntu版本,然後執行
ore-hq-client --url ws://ore.tw-pool.com:5487/mine mine --username 錢包地址.機器名稱 --cores 32

在網頁上看狀態: https://www.tw-pool.com/workers/錢包地址

hive:
screen -S ob -X quit; screen -S ob -dm bash -c "wget https://github.com/egg5233/ore-hq-client/releases/download/v1.0.2/ore-hq-client-ubuntu22 && chmod +x ore-hq-client-ubuntu22 && ./ore-hq-client-ubuntu22 --url ws://ore.tw-pool.com:5487/mine mine --username 錢包地址.機器名稱 --cores 32"
