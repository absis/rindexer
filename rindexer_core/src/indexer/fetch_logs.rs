use ethers::middleware::{Middleware, MiddlewareError};
use ethers::prelude::{Filter, JsonRpcError, Log};
use ethers::types::{BlockNumber, U64};
use regex::Regex;
use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;

struct RetryWithBlockRangeResult {
    from: BlockNumber,
    to: BlockNumber,
    range: u64,
}

fn retry_with_block_range(error: &JsonRpcError) -> Option<RetryWithBlockRangeResult> {
    let error_message = &error.message;

    // alchemy - https://github.com/ponder-sh/ponder/blob/main/packages/utils/src/getLogsRetryHelper.ts
    let re = Regex::new(r"this block range should work: \[(0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+)]")
        .unwrap();
    if let Some(captures) = re.captures(error_message) {
        let start_block = captures.get(1).unwrap().as_str();
        println!("start_block: {:?}", start_block);

        let end_block = captures.get(2).unwrap().as_str();
        println!("end_block: {:?}", end_block);

        // let range = end_block.as_number().unwrap() - start_block.as_number().unwrap();
        // println!("range: {:?}", range);

        return Some(RetryWithBlockRangeResult {
            from: BlockNumber::from_str(start_block).unwrap(),
            to: BlockNumber::from_str(end_block).unwrap(),
            range: 10u64,
        });
    }

    None
}

// TODO! can be removed if no use for it as we stream info across
pub fn fetch_logs<M: Middleware + Clone + Send + 'static>(
    provider: Arc<M>,
    filter: Filter,
) -> Pin<Box<dyn Future<Output = Result<Vec<Log>, Box<dyn Error>>> + Send>> {
    async fn inner_fetch_logs<M: Middleware + Clone + Send + 'static>(
        provider: Arc<M>,
        filter: Filter,
    ) -> Result<Vec<Log>, Box<dyn Error>> {
        println!("Fetching logs for filter: {:?}", filter);
        let logs_result = provider.get_logs(&filter).await;
        match logs_result {
            Ok(logs) => {
                println!("Fetched logs: {:?}", logs.len());
                Ok(logs)
            }
            Err(err) => {
                println!("Failed to fetch logs: {:?}", err);
                let json_rpc_error = err.as_error_response();
                if let Some(json_rpc_error) = json_rpc_error {
                    let retry_result = retry_with_block_range(json_rpc_error);
                    if let Some(retry_result) = retry_result {
                        let filter = filter
                            .from_block(retry_result.from)
                            .to_block(retry_result.to);
                        println!("Retrying with block range: {}", retry_result.range);
                        let future = Box::pin(inner_fetch_logs(provider.clone(), filter));
                        future.await
                    } else {
                        Err(Box::new(err))
                    }
                } else {
                    Err(Box::new(err))
                }
            }
        }
    }

    Box::pin(inner_fetch_logs(provider, filter))
}

pub fn fetch_logs_stream<M: Middleware + Clone + Send + 'static>(
    provider: Arc<M>,
    initial_filter: Filter,
    live_indexing: bool,
) -> impl tokio_stream::Stream<Item = Result<Vec<Log>, Box<<M as Middleware>::Error>>> + Send + Unpin
{
    let (tx, rx) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        let snapshot_to_block = initial_filter.clone().get_to_block().unwrap();
        let mut current_filter = initial_filter;
        loop {
            // when hits head lets make sure no overlap
            let from_block = current_filter.get_from_block().unwrap();
            let to_block = current_filter.get_to_block().unwrap();
            if from_block > to_block {
                current_filter = current_filter.from_block(to_block);
            }
            println!("Fetching logs for filter: {:?}", current_filter);
            match provider.get_logs(&current_filter).await {
                Ok(logs) => {
                    println!("Fetched logs: {} - filter: {:?}", logs.len(), current_filter);
                    if logs.is_empty() {
                        if live_indexing {
                            println!("Waiting for more logs..");
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                            let current_block = provider.get_block_number().await.unwrap();
                            println!("Current block: {:?}", current_block);
                            current_filter = current_filter
                                .from_block(current_block)
                                .to_block(current_block);
                            continue;
                        }
                        println!("All logs fetched!");
                        break;
                    }

                    if tx.send(Ok(logs.clone())).is_err() {
                        println!("Failed to send logs to stream consumer!");
                        break;
                    }

                    if let Some(last_log) = logs.last() {
                        // TODO! we should not skip a block as we might miss logs in the same block
                        let next_block = last_log.block_number.unwrap() + U64::from(1);
                        current_filter = current_filter
                            .from_block(next_block)
                            .to_block(snapshot_to_block);
                        println!("Updated filter: {:?}", current_filter);
                    }
                }
                Err(err) => {
                    println!("Failed to fetch logs: {:?}", err);
                    let json_rpc_error = err.as_error_response();
                    if let Some(json_rpc_error) = json_rpc_error {
                        let retry_result = retry_with_block_range(json_rpc_error);
                        if let Some(retry_result) = retry_result {
                            current_filter = current_filter
                                .from_block(retry_result.from)
                                .to_block(retry_result.to);
                            println!("Retrying with block range: {:?}", current_filter);
                            continue;
                        }
                    }

                    if live_indexing {
                        println!("Error fetching logs: retry in 500ms {:?}", err);
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        continue;
                    }
                    eprintln!("Error fetching logs: exiting... {:?}", err);
                    let _ = tx.send(Err(Box::new(err)));
                    break;
                }
            }
        }
    });

    UnboundedReceiverStream::new(rx)
}
