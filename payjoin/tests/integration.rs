mod integration {
    use std::collections::HashMap;
    use std::env;
    use std::str::FromStr;

    use bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE;
    use bitcoin::psbt::{Input as PsbtInput, Psbt};
    use bitcoin::transaction::InputWeightPrediction;
    use bitcoin::{Amount, FeeRate, OutPoint, TxIn, TxOut, Weight};
    use bitcoind::bitcoincore_rpc::json::{AddressType, WalletProcessPsbtResult};
    use bitcoind::bitcoincore_rpc::{self, RpcApi};
    use log::{log_enabled, Level};
    use once_cell::sync::{Lazy, OnceCell};
    use payjoin::receive::v1::build_v1_pj_uri;
    use payjoin::receive::InputPair;
    use payjoin::{PjUri, Request, Uri};
    use tracing_subscriber::{EnvFilter, FmtSubscriber};
    use url::Url;

    type BoxError = Box<dyn std::error::Error + 'static>;

    static INIT_TRACING: OnceCell<()> = OnceCell::new();
    static EXAMPLE_URL: Lazy<Url> =
        Lazy::new(|| Url::parse("https://example.com").expect("Invalid Url"));

    mod v1 {
        use log::debug;
        use payjoin::send::v1::SenderBuilder;
        use payjoin::UriExt;

        use super::*;

        #[test]
        fn v1_to_v1_p2pkh() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(
                Some(AddressType::Legacy),
                Some(AddressType::Legacy),
            )?;
            do_v1_to_v1(sender, receiver, true)
        }

        #[test]
        fn v1_to_v1_nested_p2wpkh() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(
                Some(AddressType::P2shSegwit),
                Some(AddressType::P2shSegwit),
            )?;
            do_v1_to_v1(sender, receiver, false)
        }

        #[test]
        fn v1_to_v1_p2wpkh() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(
                Some(AddressType::Bech32),
                Some(AddressType::Bech32),
            )?;
            do_v1_to_v1(sender, receiver, false)
        }

        // TODO: Not supported by bitcoind 0_21_2. Later versions fail for unknown reasons
        //#[test]
        //fn v1_to_v1_taproot() -> Result<(), BoxError> {
        //    init_tracing();
        //    let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(
        //        Some(AddressType::Bech32m),
        //        Some(AddressType::Bech32m),
        //    )?;
        //    do_v1_to_v1(sender, receiver, false)
        //}

        fn do_v1_to_v1(
            sender: bitcoincore_rpc::Client,
            receiver: bitcoincore_rpc::Client,
            is_p2pkh: bool,
        ) -> Result<(), BoxError> {
            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.get_new_address(None, None)?.assume_checked();
            let mut pj_uri = build_v1_pj_uri(&pj_receiver_address, &EXAMPLE_URL, false);
            pj_uri.amount = Some(Amount::ONE_BTC);

            // **********************
            // Inside the Sender:
            // Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let uri = Uri::from_str(&pj_uri.to_string())
                .unwrap()
                .assume_checked()
                .check_pj_supported()
                .unwrap();
            let psbt = build_original_psbt(&sender, &uri)?;
            debug!("Original psbt: {:#?}", psbt);
            let (req, ctx) = SenderBuilder::new(psbt, uri)
                .build_with_additional_fee(Amount::from_sat(10000), None, FeeRate::ZERO, false)?
                .extract_v1()?;
            let headers = HeaderMock::new(&req.body, req.content_type);

            // **********************
            // Inside the Receiver:
            // this data would transit from one party to another over the network in production
            let response = handle_v1_pj_request(req, headers, &receiver, None, None, None)?;
            // this response would be returned as http response to the sender

            // **********************
            // Inside the Sender:
            // Sender checks, signs, finalizes, extracts, and broadcasts
            let checked_payjoin_proposal_psbt = ctx.process_response(&response)?;
            let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
            sender.send_raw_transaction(&payjoin_tx)?;

            // Check resulting transaction and balances
            let mut predicted_tx_weight = predicted_tx_weight(&payjoin_tx);
            if is_p2pkh {
                // HACK:
                // bitcoin-cli always grinds signatures to save 1 byte (4WU) and simplify fee
                // estimates. This results in the original PSBT having a fee of 219 sats
                // instead of the "worst case" 220 sats assuming a maximum-size signature.
                // Note that this also affects weight predictions for segwit inputs, but the
                // resulting signatures are only 1WU smaller (.25 bytes) and therefore don't
                // affect our weight predictions for the original sender inputs.
                predicted_tx_weight -= Weight::from_non_witness_data_size(1);
            }
            let network_fees = predicted_tx_weight * FeeRate::BROADCAST_MIN;
            assert_eq!(payjoin_tx.input.len(), 2);
            assert_eq!(payjoin_tx.output.len(), 2);
            assert_eq!(receiver.get_balances()?.mine.untrusted_pending, Amount::from_btc(51.0)?);
            assert_eq!(
                sender.get_balances()?.mine.untrusted_pending,
                Amount::from_btc(49.0)? - network_fees
            );
            Ok(())
        }

        #[test]
        fn disallow_mixed_input_scripts() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(
                Some(AddressType::Bech32),
                Some(AddressType::P2shSegwit),
            )?;

            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.get_new_address(None, None)?.assume_checked();
            let mut pj_uri = build_v1_pj_uri(&pj_receiver_address, &EXAMPLE_URL, false);
            pj_uri.amount = Some(Amount::ONE_BTC);

            // **********************
            // Inside the Sender:
            // Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let uri = Uri::from_str(&pj_uri.to_string())
                .unwrap()
                .assume_checked()
                .check_pj_supported()
                .unwrap();
            let psbt = build_original_psbt(&sender, &uri)?;
            debug!("Original psbt: {:#?}", psbt);
            let (req, _ctx) = SenderBuilder::new(psbt, uri)
                .build_with_additional_fee(Amount::from_sat(10000), None, FeeRate::ZERO, false)?
                .extract_v1()?;
            let headers = HeaderMock::new(&req.body, req.content_type);

            // **********************
            // Inside the Receiver:
            // This should error because the receiver is attempting to introduce mixed input script types
            assert!(handle_v1_pj_request(req, headers, &receiver, None, None, None).is_err());
            Ok(())
        }
    }

    #[cfg(all(feature = "io", feature = "v2", feature = "_danger-local-https"))]
    mod v2 {
        use std::sync::Arc;
        use std::time::Duration;

        use bitcoin::Address;
        use http::StatusCode;
        use payjoin::receive::v2::{PayjoinProposal, Receiver, UncheckedProposal};
        use payjoin::send::v2::SenderBuilder;
        use payjoin::{OhttpKeys, PjUri, UriExt};
        use reqwest::{Client, ClientBuilder, Error, Response};
        use testcontainers_modules::redis::Redis;
        use testcontainers_modules::testcontainers::clients::Cli;

        use super::*;

        type BoxSendSyncError = Box<dyn std::error::Error + Send + Sync>;

        static TESTS_TIMEOUT: Lazy<Duration> = Lazy::new(|| Duration::from_secs(20));
        static WAIT_SERVICE_INTERVAL: Lazy<Duration> = Lazy::new(|| Duration::from_secs(3));

        #[tokio::test]
        async fn test_bad_ohttp_keys() {
            let bad_ohttp_keys =
                OhttpKeys::from_str("OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC")
                    .expect("Invalid OhttpKeys");

            let (cert, key) = local_cert_key();
            let docker: Cli = Cli::default();
            let db = docker.run(Redis);
            let db_host = format!("127.0.0.1:{}", db.get_host_port_ipv4(6379));

            let (port, directory_handle) = init_directory(db_host, (cert.clone(), key))
                .await
                .expect("Failed to init directory");
            let directory = Url::parse(&format!("https://localhost:{}", port)).unwrap();

            tokio::select!(
                err = directory_handle => panic!("Directory server exited early: {:?}", err),
                res = try_request_with_bad_keys(directory, bad_ohttp_keys, cert) => {
                    assert_eq!(
                        res.unwrap().headers().get("content-type").unwrap(),
                        "application/problem+json"
                    );
                }
            );

            async fn try_request_with_bad_keys(
                directory: Url,
                bad_ohttp_keys: OhttpKeys,
                cert_der: Vec<u8>,
            ) -> Result<Response, Error> {
                let agent = Arc::new(http_agent(cert_der.clone()).unwrap());
                wait_for_service_ready(directory.clone(), agent.clone()).await.unwrap();
                let mock_ohttp_relay = directory.clone(); // pass through to directory
                let mock_address = Address::from_str("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4")
                    .unwrap()
                    .assume_checked();
                let mut bad_initializer =
                    Receiver::new(mock_address, directory, bad_ohttp_keys, None);
                let (req, _ctx) = bad_initializer
                    .extract_req(&mock_ohttp_relay)
                    .expect("Failed to extract request");
                agent.post(req.url).body(req.body).send().await
            }
        }

        #[tokio::test]
        async fn test_session_expiration() {
            init_tracing();
            let (cert, key) = local_cert_key();
            let docker: Cli = Cli::default();
            let db = docker.run(Redis);
            let db_host = format!("127.0.0.1:{}", db.get_host_port_ipv4(6379));

            let (directory_port, directory_handle) = init_directory(db_host, (cert.clone(), key))
                .await
                .expect("Failed to init directory");
            let directory = Url::parse(&format!("https://localhost:{}", directory_port)).unwrap();
            let gateway_origin = http::Uri::from_str(directory.as_str()).unwrap();
            let (ohttp_relay_port, ohttp_relay_handle) =
                ohttp_relay::listen_tcp_on_free_port(gateway_origin)
                    .await
                    .expect("Failed to init ohttp relay");
            let ohttp_relay =
                Url::parse(&format!("http://localhost:{}", ohttp_relay_port)).unwrap();
            tokio::select!(
            err = ohttp_relay_handle => panic!("Ohttp relay exited early: {:?}", err),
            err = directory_handle => panic!("Directory server exited early: {:?}", err),
            res = do_expiration_tests(ohttp_relay, directory, cert) => assert!(res.is_ok(), "v2 send receive failed: {:#?}", res)
            );

            async fn do_expiration_tests(
                ohttp_relay: Url,
                directory: Url,
                cert_der: Vec<u8>,
            ) -> Result<(), BoxError> {
                let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
                let agent = Arc::new(http_agent(cert_der.clone())?);
                wait_for_service_ready(ohttp_relay.clone(), agent.clone()).await.unwrap();
                wait_for_service_ready(directory.clone(), agent.clone()).await.unwrap();
                let ohttp_keys = payjoin::io::fetch_ohttp_keys_with_cert(
                    ohttp_relay.clone(),
                    directory.clone(),
                    cert_der,
                )
                .await?;

                // **********************
                // Inside the Receiver:
                let address = receiver.get_new_address(None, None)?.assume_checked();
                // test session with expiry in the past
                let mut expired_receiver = Receiver::new(
                    address.clone(),
                    directory.clone(),
                    ohttp_keys.clone(),
                    Some(Duration::from_secs(0)),
                );
                match expired_receiver.extract_req(&ohttp_relay) {
                    // Internal error types are private, so check against a string
                    Err(err) => assert!(err.to_string().contains("expired")),
                    _ => panic!("Expired receive session should error"),
                };

                // **********************
                // Inside the Sender:
                let psbt = build_original_psbt(&sender, &expired_receiver.pj_uri())?;
                // Test that an expired pj_url errors
                let expired_req_ctx = SenderBuilder::new(psbt, expired_receiver.pj_uri())
                    .build_non_incentivizing(FeeRate::BROADCAST_MIN)?;
                match expired_req_ctx.extract_v2(directory.to_owned()) {
                    // Internal error types are private, so check against a string
                    Err(err) => assert!(err.to_string().contains("expired")),
                    _ => panic!("Expired send session should error"),
                };
                Ok(())
            }
        }

        #[tokio::test]
        async fn v2_to_v2() {
            init_tracing();
            let (cert, key) = local_cert_key();
            let docker: Cli = Cli::default();
            let db = docker.run(Redis);
            let db_host = format!("127.0.0.1:{}", db.get_host_port_ipv4(6379));

            let (directory_port, directory_handle) = init_directory(db_host, (cert.clone(), key))
                .await
                .expect("Failed to init directory");
            let directory = Url::parse(&format!("https://localhost:{}", directory_port)).unwrap();
            let gateway_origin = http::Uri::from_str(directory.as_str()).unwrap();
            let (ohttp_relay_port, ohttp_relay_handle) =
                ohttp_relay::listen_tcp_on_free_port(gateway_origin)
                    .await
                    .expect("Failed to init ohttp relay");
            let ohttp_relay =
                Url::parse(&format!("http://localhost:{}", ohttp_relay_port)).unwrap();
            tokio::select!(
            err = ohttp_relay_handle => panic!("Ohttp relay exited early: {:?}", err),
            err = directory_handle => panic!("Directory server exited early: {:?}", err),
            res = do_v2_send_receive(ohttp_relay, directory, cert) => assert!(res.is_ok(), "v2 send receive failed: {:#?}", res)
            );

            async fn do_v2_send_receive(
                ohttp_relay: Url,
                directory: Url,
                cert_der: Vec<u8>,
            ) -> Result<(), BoxError> {
                let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
                let agent = Arc::new(http_agent(cert_der.clone())?);
                wait_for_service_ready(ohttp_relay.clone(), agent.clone()).await.unwrap();
                wait_for_service_ready(directory.clone(), agent.clone()).await.unwrap();
                let ohttp_keys = payjoin::io::fetch_ohttp_keys_with_cert(
                    ohttp_relay.clone(),
                    directory.clone(),
                    cert_der.clone(),
                )
                .await?;
                // **********************
                // Inside the Receiver:
                let address = receiver.get_new_address(None, None)?.assume_checked();

                // test session with expiry in the future
                let mut session =
                    Receiver::new(address.clone(), directory.clone(), ohttp_keys.clone(), None);
                println!("session: {:#?}", &session);
                let pj_uri_string = session.pj_uri().to_string();
                // Poll receive request
                let mock_ohttp_relay = directory.clone();
                let (req, ctx) = session.extract_req(&mock_ohttp_relay)?;
                let response = agent.post(req.url).body(req.body).send().await?;
                assert!(response.status().is_success());
                let response_body =
                    session.process_res(response.bytes().await?.to_vec().as_slice(), ctx).unwrap();
                // No proposal yet since sender has not responded
                assert!(response_body.is_none());

                // **********************
                // Inside the Sender:
                // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
                let pj_uri = Uri::from_str(&pj_uri_string)
                    .unwrap()
                    .assume_checked()
                    .check_pj_supported()
                    .unwrap();
                let psbt = build_sweep_psbt(&sender, &pj_uri)?;
                let req_ctx = SenderBuilder::new(psbt.clone(), pj_uri.clone())
                    .build_recommended(FeeRate::BROADCAST_MIN)?;
                let (Request { url, body, content_type, .. }, send_ctx) =
                    req_ctx.extract_v2(mock_ohttp_relay.to_owned())?;
                let response = agent
                    .post(url.clone())
                    .header("Content-Type", content_type)
                    .body(body.clone())
                    .send()
                    .await
                    .unwrap();
                log::info!("Response: {:#?}", &response);
                assert!(response.status().is_success());
                let send_ctx = send_ctx.process_response(&response.bytes().await?)?;
                // POST Original PSBT

                // **********************
                // Inside the Receiver:

                // GET fallback psbt
                let (req, ctx) = session.extract_req(&mock_ohttp_relay)?;
                let response = agent.post(req.url).body(req.body).send().await?;
                // POST payjoin
                let proposal =
                    session.process_res(response.bytes().await?.to_vec().as_slice(), ctx)?.unwrap();
                let mut payjoin_proposal = handle_directory_proposal(&receiver, proposal, None);
                assert!(!payjoin_proposal.is_output_substitution_disabled());
                let (req, ctx) = payjoin_proposal.extract_v2_req(&mock_ohttp_relay)?;
                let response = agent
                    .post(req.url)
                    .header("Content-Type", req.content_type)
                    .body(req.body)
                    .send()
                    .await?;
                payjoin_proposal.process_res(&response.bytes().await?, ctx)?;

                // **********************
                // Inside the Sender:
                // Sender checks, signs, finalizes, extracts, and broadcasts
                // Replay post fallback to get the response
                let (Request { url, body, content_type, .. }, ohttp_ctx) =
                    send_ctx.extract_req(mock_ohttp_relay.to_owned())?;
                let response = agent
                    .post(url.clone())
                    .header("Content-Type", content_type)
                    .body(body.clone())
                    .send()
                    .await
                    .unwrap();
                log::info!("Response: {:#?}", &response);
                let checked_payjoin_proposal_psbt =
                    send_ctx.process_response(&response.bytes().await?, ohttp_ctx)?.unwrap();
                let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
                sender.send_raw_transaction(&payjoin_tx)?;
                log::info!("sent");

                // Check resulting transaction and balances
                let network_fees = predicted_tx_weight(&payjoin_tx) * FeeRate::BROADCAST_MIN;
                // Sender sent the entire value of their utxo to receiver (minus fees)
                assert_eq!(payjoin_tx.input.len(), 2);
                assert_eq!(payjoin_tx.output.len(), 1);
                assert_eq!(
                    receiver.get_balances()?.mine.untrusted_pending,
                    Amount::from_btc(100.0)? - network_fees
                );
                assert_eq!(sender.get_balances()?.mine.untrusted_pending, Amount::from_btc(0.0)?);
                Ok(())
            }
        }

        #[tokio::test]
        async fn v2_to_v2_mixed_input_script_types() {
            init_tracing();
            let (cert, key) = local_cert_key();
            let docker: Cli = Cli::default();
            let db = docker.run(Redis);
            let db_host = format!("127.0.0.1:{}", db.get_host_port_ipv4(6379));

            let (directory_port, directory_handle) = init_directory(db_host, (cert.clone(), key))
                .await
                .expect("Failed to init directory");
            let directory = Url::parse(&format!("https://localhost:{}", directory_port)).unwrap();
            let gateway_origin = http::Uri::from_str(directory.as_str()).unwrap();
            let (ohttp_relay_port, ohttp_relay_handle) =
                ohttp_relay::listen_tcp_on_free_port(gateway_origin)
                    .await
                    .expect("Failed to init ohttp relay");
            let ohttp_relay =
                Url::parse(&format!("http://localhost:{}", ohttp_relay_port)).unwrap();
            tokio::select!(
            err = ohttp_relay_handle => panic!("Ohttp relay exited early: {:?}", err),
            err = directory_handle => panic!("Directory server exited early: {:?}", err),
            res = do_v2_send_receive(ohttp_relay, directory, cert) => assert!(res.is_ok(), "v2 send receive failed: {:#?}", res)
            );

            async fn do_v2_send_receive(
                ohttp_relay: Url,
                directory: Url,
                cert_der: Vec<u8>,
            ) -> Result<(), BoxError> {
                let (bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
                let agent = Arc::new(http_agent(cert_der.clone())?);
                wait_for_service_ready(ohttp_relay.clone(), agent.clone()).await.unwrap();
                wait_for_service_ready(directory.clone(), agent.clone()).await.unwrap();
                let ohttp_keys = payjoin::io::fetch_ohttp_keys_with_cert(
                    ohttp_relay.clone(),
                    directory.clone(),
                    cert_der,
                )
                .await?;
                // **********************
                // Inside the Receiver:
                // make utxos with different script types

                let legacy_address =
                    receiver.get_new_address(None, Some(AddressType::Legacy))?.assume_checked();
                let nested_segwit_address =
                    receiver.get_new_address(None, Some(AddressType::P2shSegwit))?.assume_checked();
                let segwit_address =
                    receiver.get_new_address(None, Some(AddressType::Bech32))?.assume_checked();
                // TODO:
                //let taproot_address =
                //    receiver.get_new_address(None, Some(AddressType::Bech32m))?.assume_checked();
                bitcoind.client.generate_to_address(1, &legacy_address)?;
                bitcoind.client.generate_to_address(1, &nested_segwit_address)?;
                bitcoind.client.generate_to_address(101, &segwit_address)?;
                let receiver_utxos = receiver
                    .list_unspent(
                        None,
                        None,
                        Some(&[&legacy_address, &nested_segwit_address, &segwit_address]),
                        None,
                        None,
                    )
                    .unwrap();
                assert_eq!(3, receiver_utxos.len(), "receiver doesn't have enough UTXOs");
                assert_eq!(
                    Amount::from_btc(150.0)?,
                    receiver_utxos.iter().fold(Amount::ZERO, |acc, txo| acc + txo.amount),
                    "receiver doesn't have enough bitcoin"
                );

                let address = receiver.get_new_address(None, None)?.assume_checked();

                // test session with expiry in the future
                let mut session =
                    Receiver::new(address.clone(), directory.clone(), ohttp_keys.clone(), None);
                println!("session: {:#?}", &session);
                let pj_uri_string = session.pj_uri().to_string();
                // Poll receive request
                let mock_ohttp_relay = directory.clone();
                let (req, ctx) = session.extract_req(&mock_ohttp_relay)?;
                let response = agent.post(req.url).body(req.body).send().await?;
                assert!(response.status().is_success());
                let response_body = session.process_res(&response.bytes().await?, ctx).unwrap();
                // No proposal yet since sender has not responded
                assert!(response_body.is_none());

                // **********************
                // Inside the Sender:
                // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
                let pj_uri = Uri::from_str(&pj_uri_string)
                    .unwrap()
                    .assume_checked()
                    .check_pj_supported()
                    .unwrap();
                let psbt = build_sweep_psbt(&sender, &pj_uri)?;
                let req_ctx = SenderBuilder::new(psbt.clone(), pj_uri.clone())
                    .build_recommended(FeeRate::BROADCAST_MIN)?;
                let (Request { url, body, content_type, .. }, post_ctx) =
                    req_ctx.extract_v2(mock_ohttp_relay.to_owned())?;
                let response = agent
                    .post(url.clone())
                    .header("Content-Type", content_type)
                    .body(body.clone())
                    .send()
                    .await
                    .unwrap();
                log::info!("Response: {:#?}", &response);
                assert!(response.status().is_success());
                let get_ctx = post_ctx.process_response(&response.bytes().await?)?;
                let (Request { url, body, content_type, .. }, ohttp_ctx) =
                    get_ctx.extract_req(mock_ohttp_relay.to_owned())?;
                let response = agent
                    .post(url.clone())
                    .header("Content-Type", content_type)
                    .body(body.clone())
                    .send()
                    .await?;
                // No response body yet since we are async and pushed fallback_psbt to the buffer
                assert!(get_ctx.process_response(&response.bytes().await?, ohttp_ctx)?.is_none());

                // **********************
                // Inside the Receiver:

                // GET fallback psbt
                let (req, ctx) = session.extract_req(&mock_ohttp_relay)?;
                let response = agent.post(req.url).body(req.body).send().await?;
                // POST payjoin
                let proposal =
                    session.process_res(response.bytes().await?.to_vec().as_slice(), ctx)?.unwrap();
                let inputs = receiver_utxos.into_iter().map(input_pair_from_list_unspent).collect();
                let mut payjoin_proposal =
                    handle_directory_proposal(&receiver, proposal, Some(inputs));
                assert!(!payjoin_proposal.is_output_substitution_disabled());
                let (req, ctx) = payjoin_proposal.extract_v2_req(&mock_ohttp_relay)?;
                let response = agent.post(req.url).body(req.body).send().await?;
                payjoin_proposal.process_res(&response.bytes().await?, ctx)?;

                // **********************
                // Inside the Sender:
                // Sender checks, signs, finalizes, extracts, and broadcasts
                // Replay post fallback to get the response
                let (Request { url, body, content_type, .. }, ohttp_ctx) =
                    get_ctx.extract_req(mock_ohttp_relay.to_owned())?;
                let response = agent
                    .post(url.clone())
                    .header("Content-Type", content_type)
                    .body(body.clone())
                    .send()
                    .await?;
                let checked_payjoin_proposal_psbt =
                    get_ctx.process_response(&response.bytes().await?, ohttp_ctx)?.unwrap();
                let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
                sender.send_raw_transaction(&payjoin_tx)?;
                log::info!("sent");

                // Check resulting transaction and balances
                let network_fees = predicted_tx_weight(&payjoin_tx) * FeeRate::BROADCAST_MIN;
                // Sender sent the entire value of their utxo to receiver (minus fees)
                assert_eq!(payjoin_tx.input.len(), 4);
                assert_eq!(payjoin_tx.output.len(), 1);
                assert_eq!(
                    receiver.get_balances()?.mine.untrusted_pending,
                    Amount::from_btc(200.0)? - network_fees
                );
                assert_eq!(sender.get_balances()?.mine.untrusted_pending, Amount::from_btc(0.0)?);
                Ok(())
            }
        }

        #[test]
        fn v2_to_v1() -> Result<(), BoxError> {
            init_tracing();
            let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.get_new_address(None, None)?.assume_checked();
            let mut pj_uri = build_v1_pj_uri(&pj_receiver_address, &EXAMPLE_URL, false);
            pj_uri.amount = Some(Amount::ONE_BTC);

            // **********************
            // Inside the Sender:
            // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let pj_uri = Uri::from_str(&pj_uri.to_string())
                .unwrap()
                .assume_checked()
                .check_pj_supported()
                .unwrap();
            let psbt = build_original_psbt(&sender, &pj_uri)?;
            let req_ctx = SenderBuilder::new(psbt.clone(), pj_uri.clone())
                .build_recommended(FeeRate::BROADCAST_MIN)?;
            let (req, ctx) = req_ctx.extract_v1()?;
            let headers = HeaderMock::new(&req.body, req.content_type);

            // **********************
            // Inside the Receiver:
            // this data would transit from one party to another over the network in production
            let response = handle_v1_pj_request(req, headers, &receiver, None, None, None)?;
            // this response would be returned as http response to the sender

            // **********************
            // Inside the Sender:
            // Sender checks, signs, finalizes, extracts, and broadcasts
            let checked_payjoin_proposal_psbt = ctx.process_response(&mut response.as_bytes())?;
            let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
            sender.send_raw_transaction(&payjoin_tx)?;

            // Check resulting transaction and balances
            let network_fees = predicted_tx_weight(&payjoin_tx) * FeeRate::BROADCAST_MIN;
            assert_eq!(payjoin_tx.input.len(), 2);
            assert_eq!(payjoin_tx.output.len(), 2);
            assert_eq!(receiver.get_balances()?.mine.untrusted_pending, Amount::from_btc(51.0)?);
            assert_eq!(
                sender.get_balances()?.mine.untrusted_pending,
                Amount::from_btc(49.0)? - network_fees
            );
            Ok(())
        }

        #[tokio::test]
        async fn v1_to_v2() {
            init_tracing();
            let (cert, key) = local_cert_key();
            let docker: Cli = Cli::default();
            let db = docker.run(Redis);
            let db_host = format!("127.0.0.1:{}", db.get_host_port_ipv4(6379));
            let (directory_port, directory_handle) = init_directory(db_host, (cert.clone(), key))
                .await
                .expect("Failed to init directory");
            let directory = Url::parse(&format!("https://localhost:{}", directory_port)).unwrap();
            let gateway_origin = http::Uri::from_str(directory.as_str()).unwrap();
            let (ohttp_relay_port, ohttp_relay_handle) =
                ohttp_relay::listen_tcp_on_free_port(gateway_origin)
                    .await
                    .expect("Failed to init ohttp relay");
            let ohttp_relay =
                Url::parse(&format!("http://localhost:{}", ohttp_relay_port)).unwrap();
            tokio::select!(
            err = ohttp_relay_handle => panic!("Ohttp relay exited early: {:?}", err),
            err = directory_handle => panic!("Directory server exited early: {:?}", err),
            res = do_v1_to_v2(ohttp_relay, directory, cert) => assert!(res.is_ok()),
            );

            async fn do_v1_to_v2(
                ohttp_relay: Url,
                directory: Url,
                cert_der: Vec<u8>,
            ) -> Result<(), BoxError> {
                let (_bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
                let agent: Arc<Client> = Arc::new(http_agent(cert_der.clone())?);
                wait_for_service_ready(ohttp_relay.clone(), agent.clone()).await?;
                wait_for_service_ready(directory.clone(), agent.clone()).await?;
                let ohttp_keys = payjoin::io::fetch_ohttp_keys_with_cert(
                    ohttp_relay.clone(),
                    directory.clone(),
                    cert_der.clone(),
                )
                .await?;
                let address = receiver.get_new_address(None, None)?.assume_checked();

                let mut session =
                    Receiver::new(address, directory.clone(), ohttp_keys.clone(), None);

                let pj_uri_string = session.pj_uri().to_string();

                // **********************
                // Inside the V1 Sender:
                // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
                let pj_uri = Uri::from_str(&pj_uri_string)
                    .unwrap()
                    .assume_checked()
                    .check_pj_supported()
                    .unwrap();
                let psbt = build_original_psbt(&sender, &pj_uri)?;
                let (Request { url, body, content_type, .. }, send_ctx) =
                    SenderBuilder::new(psbt, pj_uri)
                        .build_with_additional_fee(
                            Amount::from_sat(10000),
                            None,
                            FeeRate::ZERO,
                            false,
                        )?
                        .extract_v1()?;
                log::info!("send fallback v1 to offline receiver fail");
                let res = agent
                    .post(url.clone())
                    .header("Content-Type", content_type)
                    .body(body.clone())
                    .send()
                    .await;
                assert!(res.as_ref().unwrap().status() == StatusCode::SERVICE_UNAVAILABLE);

                // **********************
                // Inside the Receiver:
                let agent_clone: Arc<Client> = agent.clone();
                let receiver: Arc<bitcoincore_rpc::Client> = Arc::new(receiver);
                let receiver_clone = receiver.clone();
                let mock_ohttp_relay = directory.clone();
                let receiver_loop = tokio::task::spawn(async move {
                    let agent_clone = agent_clone.clone();
                    let (response, ctx) = loop {
                        let (req, ctx) = session.extract_req(&mock_ohttp_relay).unwrap();
                        let response = agent_clone.post(req.url).body(req.body).send().await?;

                        if response.status() == 200 {
                            break (response.bytes().await?.to_vec(), ctx);
                        } else if response.status() == 202 {
                            log::info!(
                                "No response yet for POST payjoin request, retrying some seconds"
                            );
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        } else {
                            log::error!("Unexpected response status: {}", response.status());
                            panic!("Unexpected response status: {}", response.status())
                        }
                    };
                    let proposal = session.process_res(response.as_slice(), ctx).unwrap().unwrap();
                    let mut payjoin_proposal =
                        handle_directory_proposal(&receiver_clone, proposal, None);
                    assert!(payjoin_proposal.is_output_substitution_disabled());
                    // Respond with payjoin psbt within the time window the sender is willing to wait
                    // this response would be returned as http response to the sender
                    let (req, ctx) = payjoin_proposal.extract_v2_req(&mock_ohttp_relay).unwrap();
                    let response = agent_clone.post(req.url).body(req.body).send().await?;
                    payjoin_proposal
                        .process_res(&response.bytes().await?, ctx)
                        .map_err(|e| e.to_string())?;
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                });

                // **********************
                // send fallback v1 to online receiver
                log::info!("send fallback v1 to online receiver should succeed");
                let response =
                    agent.post(url).header("Content-Type", content_type).body(body).send().await?;
                log::info!("Response: {:#?}", &response);
                assert!(response.status().is_success());

                let res = response.bytes().await?.to_vec();
                let checked_payjoin_proposal_psbt =
                    send_ctx.process_response(&mut res.as_slice())?;
                let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
                sender.send_raw_transaction(&payjoin_tx)?;
                log::info!("sent");
                assert!(
                    receiver_loop.await.is_ok(),
                    "The spawned task panicked or returned an error"
                );

                // Check resulting transaction and balances
                let network_fees = predicted_tx_weight(&payjoin_tx) * FeeRate::BROADCAST_MIN;
                assert_eq!(payjoin_tx.input.len(), 2);
                assert_eq!(payjoin_tx.output.len(), 2);
                assert_eq!(
                    receiver.get_balances()?.mine.untrusted_pending,
                    Amount::from_btc(51.0)?
                );
                assert_eq!(
                    sender.get_balances()?.mine.untrusted_pending,
                    Amount::from_btc(49.0)? - network_fees
                );
                Ok(())
            }
        }

        async fn init_directory(
            db_host: String,
            local_cert_key: (Vec<u8>, Vec<u8>),
        ) -> Result<(u16, tokio::task::JoinHandle<Result<(), BoxSendSyncError>>), BoxSendSyncError>
        {
            println!("Database running on {}", db_host);
            let timeout = Duration::from_secs(2);
            payjoin_directory::listen_tcp_with_tls_on_free_port(db_host, timeout, local_cert_key)
                .await
        }

        // generates or gets a DER encoded localhost cert and key.
        fn local_cert_key() -> (Vec<u8>, Vec<u8>) {
            let cert = rcgen::generate_simple_self_signed(vec![
                "0.0.0.0".to_string(),
                "localhost".to_string(),
            ])
            .expect("Failed to generate cert");
            let cert_der = cert.serialize_der().expect("Failed to serialize cert");
            let key_der = cert.serialize_private_key_der();
            (cert_der, key_der)
        }

        fn handle_directory_proposal(
            receiver: &bitcoincore_rpc::Client,
            proposal: UncheckedProposal,
            custom_inputs: Option<Vec<InputPair>>,
        ) -> PayjoinProposal {
            // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
            let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

            // Receive Check 1: Can Broadcast
            let proposal = proposal
                .check_broadcast_suitability(None, |tx| {
                    Ok(receiver
                        .test_mempool_accept(&[bitcoin::consensus::encode::serialize_hex(&tx)])
                        .unwrap()
                        .first()
                        .unwrap()
                        .allowed)
                })
                .expect("Payjoin proposal should be broadcastable");

            // Receive Check 2: receiver can't sign for proposal inputs
            let proposal = proposal
                .check_inputs_not_owned(|input| {
                    let address =
                        bitcoin::Address::from_script(input, bitcoin::Network::Regtest).unwrap();
                    Ok(receiver.get_address_info(&address).unwrap().is_mine.unwrap())
                })
                .expect("Receiver should not own any of the inputs");

            // Receive Check 3: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
            let payjoin = proposal
                .check_no_inputs_seen_before(|_| Ok(false))
                .unwrap()
                .identify_receiver_outputs(|output_script| {
                    let address =
                        bitcoin::Address::from_script(output_script, bitcoin::Network::Regtest)
                            .unwrap();
                    Ok(receiver.get_address_info(&address).unwrap().is_mine.unwrap())
                })
                .expect("Receiver should have at least one output");

            let payjoin = payjoin.commit_outputs();

            let inputs = match custom_inputs {
                Some(inputs) => inputs,
                None => {
                    let candidate_inputs = receiver
                        .list_unspent(None, None, None, None, None)
                        .unwrap()
                        .into_iter()
                        .map(input_pair_from_list_unspent);
                    let selected_input = payjoin
                        .try_preserving_privacy(candidate_inputs)
                        .map_err(|e| {
                            format!("Failed to make privacy preserving selection: {:?}", e)
                        })
                        .unwrap();
                    vec![selected_input]
                }
            };
            let payjoin = payjoin.contribute_inputs(inputs).unwrap().commit_inputs();

            // Sign and finalize the proposal PSBT
            payjoin
                .finalize_proposal(
                    |psbt: &Psbt| {
                        Ok(receiver
                            .wallet_process_psbt(
                                &psbt.to_string(),
                                None,
                                None,
                                Some(true), // check that the receiver properly clears keypaths
                            )
                            .map(|res: WalletProcessPsbtResult| Psbt::from_str(&res.psbt).unwrap())
                            .unwrap())
                    },
                    Some(FeeRate::BROADCAST_MIN),
                    FeeRate::from_sat_per_vb_unchecked(2),
                )
                .unwrap()
        }

        fn http_agent(cert_der: Vec<u8>) -> Result<Client, BoxError> {
            Ok(http_agent_builder(cert_der)?.build()?)
        }

        fn http_agent_builder(cert_der: Vec<u8>) -> Result<ClientBuilder, BoxError> {
            Ok(ClientBuilder::new()
                .danger_accept_invalid_certs(true)
                .use_rustls_tls()
                .add_root_certificate(
                    reqwest::tls::Certificate::from_der(cert_der.as_slice()).unwrap(),
                ))
        }

        async fn wait_for_service_ready(
            service_url: Url,
            agent: Arc<Client>,
        ) -> Result<(), &'static str> {
            let health_url = service_url.join("/health").map_err(|_| "Invalid URL")?;
            let start = std::time::Instant::now();

            while start.elapsed() < *TESTS_TIMEOUT {
                let request_result =
                    agent.get(health_url.as_str()).send().await.map_err(|_| "Bad request")?;
                match request_result.status() {
                    StatusCode::OK => return Ok(()),
                    StatusCode::NOT_FOUND => return Err("Endpoint not found"),
                    _ => std::thread::sleep(*WAIT_SERVICE_INTERVAL),
                }
            }

            Err("Timeout waiting for service to be ready")
        }

        fn build_sweep_psbt(
            sender: &bitcoincore_rpc::Client,
            pj_uri: &PjUri,
        ) -> Result<Psbt, BoxError> {
            let mut outputs = HashMap::with_capacity(1);
            outputs.insert(pj_uri.address.to_string(), Amount::from_btc(50.0)?);
            let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
                lock_unspent: Some(true),
                // The minimum relay feerate ensures that tests fail if the receiver would add inputs/outputs
                // that cannot be covered by the sender's additional fee contributions.
                fee_rate: Some(Amount::from_sat(DEFAULT_MIN_RELAY_TX_FEE.into())),
                subtract_fee_from_outputs: vec![0],
                ..Default::default()
            };
            let psbt = sender
                .wallet_create_funded_psbt(
                    &[], // inputs
                    &outputs,
                    None, // locktime
                    Some(options),
                    Some(true), // check that the sender properly clears keypaths
                )?
                .psbt;
            let psbt = sender.wallet_process_psbt(&psbt, None, None, None)?.psbt;
            Ok(Psbt::from_str(&psbt)?)
        }
    }

    mod batching {
        use payjoin::send::v1::SenderBuilder;
        use payjoin::UriExt;

        use super::*;

        // In this test the receiver consolidates a bunch of UTXOs into the destination output
        #[test]
        fn receiver_consolidates_utxos() -> Result<(), BoxError> {
            init_tracing();
            let (bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
            // Generate more UTXOs for the receiver
            let receiver_address =
                receiver.get_new_address(None, Some(AddressType::Bech32))?.assume_checked();
            bitcoind.client.generate_to_address(199, &receiver_address)?;
            let receiver_utxos = receiver.list_unspent(None, None, None, None, None).unwrap();
            assert_eq!(100, receiver_utxos.len(), "receiver doesn't have enough UTXOs");
            assert_eq!(
                Amount::from_btc(3700.0)?, // 48*50.0 + 52*25.0 (halving occurs every 150 blocks)
                receiver.get_balances()?.mine.trusted,
                "receiver doesn't have enough bitcoin"
            );

            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.get_new_address(None, None)?.assume_checked();
            let mut pj_uri = build_v1_pj_uri(&pj_receiver_address, &EXAMPLE_URL, false);
            pj_uri.amount = Some(Amount::ONE_BTC);

            // **********************
            // Inside the Sender:
            // Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let uri = Uri::from_str(&pj_uri.to_string())
                .unwrap()
                .assume_checked()
                .check_pj_supported()
                .unwrap();
            let psbt = build_original_psbt(&sender, &uri)?;
            log::debug!("Original psbt: {:#?}", psbt);
            let max_additional_fee = Amount::from_sat(1000);
            let (req, ctx) = SenderBuilder::new(psbt.clone(), uri)
                .build_with_additional_fee(max_additional_fee, None, FeeRate::ZERO, false)?
                .extract_v1()?;
            let headers = HeaderMock::new(&req.body, req.content_type);

            // **********************
            // Inside the Receiver:
            // this data would transit from one party to another over the network in production
            let outputs = vec![TxOut {
                value: Amount::from_btc(3700.0)?,
                script_pubkey: receiver
                    .get_new_address(None, None)?
                    .assume_checked()
                    .script_pubkey(),
            }];
            let drain_script = outputs[0].script_pubkey.clone();
            let inputs = receiver_utxos.into_iter().map(input_pair_from_list_unspent).collect();
            let response = handle_v1_pj_request(
                req,
                headers,
                &receiver,
                Some(outputs),
                Some(&drain_script),
                Some(inputs),
            )?;
            // this response would be returned as http response to the sender

            // **********************
            // Inside the Sender:
            // Sender checks, signs, finalizes, extracts, and broadcasts
            let checked_payjoin_proposal_psbt = ctx.process_response(&response)?;
            let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
            sender.send_raw_transaction(&payjoin_tx)?;

            // Check resulting transaction and balances
            let network_fees = predicted_tx_weight(&payjoin_tx) * FeeRate::BROADCAST_MIN;
            // The sender pays (original tx fee + max additional fee)
            let original_tx_fee = psbt.fee()?;
            let sender_fee = original_tx_fee + max_additional_fee;
            // The receiver pays the difference
            let receiver_fee = network_fees - sender_fee;
            assert_eq!(payjoin_tx.input.len(), 101);
            assert_eq!(payjoin_tx.output.len(), 2);
            assert_eq!(
                receiver.get_balances()?.mine.untrusted_pending,
                Amount::from_btc(3701.0)? - receiver_fee
            );
            assert_eq!(
                sender.get_balances()?.mine.untrusted_pending,
                Amount::from_btc(49.0)? - sender_fee
            );
            Ok(())
        }

        // In this test the receiver forwards part of the sender payment to another payee
        #[test]
        fn receiver_forwards_payment() -> Result<(), BoxError> {
            init_tracing();
            let (bitcoind, sender, receiver) = init_bitcoind_sender_receiver(None, None)?;
            let third_party = bitcoind.create_wallet("third-party")?;

            // Receiver creates the payjoin URI
            let pj_receiver_address = receiver.get_new_address(None, None)?.assume_checked();
            let mut pj_uri = build_v1_pj_uri(&pj_receiver_address, &EXAMPLE_URL, false);
            pj_uri.amount = Some(Amount::ONE_BTC);

            // **********************
            // Inside the Sender:
            // Sender create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let uri = Uri::from_str(&pj_uri.to_string())
                .unwrap()
                .assume_checked()
                .check_pj_supported()
                .unwrap();
            let psbt = build_original_psbt(&sender, &uri)?;
            log::debug!("Original psbt: {:#?}", psbt);
            let (req, ctx) = SenderBuilder::new(psbt.clone(), uri)
                .build_with_additional_fee(Amount::from_sat(10000), None, FeeRate::ZERO, false)?
                .extract_v1()?;
            let headers = HeaderMock::new(&req.body, req.content_type);

            // **********************
            // Inside the Receiver:
            // this data would transit from one party to another over the network in production
            let outputs = vec![
                TxOut {
                    value: Amount::from_sat(10000000),
                    script_pubkey: third_party
                        .get_new_address(None, None)?
                        .assume_checked()
                        .script_pubkey(),
                },
                TxOut {
                    value: Amount::from_sat(90000000),
                    script_pubkey: receiver
                        .get_new_address(None, None)?
                        .assume_checked()
                        .script_pubkey(),
                },
            ];
            let drain_script = outputs[1].script_pubkey.clone();
            let inputs = vec![];
            let response = handle_v1_pj_request(
                req,
                headers,
                &receiver,
                Some(outputs),
                Some(&drain_script),
                Some(inputs),
            )?;
            // this response would be returned as http response to the sender

            // **********************
            // Inside the Sender:
            // Sender checks, signs, finalizes, extracts, and broadcasts
            let checked_payjoin_proposal_psbt = ctx.process_response(&response)?;
            let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt)?;
            sender.send_raw_transaction(&payjoin_tx)?;

            // Check resulting transaction and balances
            let network_fees = predicted_tx_weight(&payjoin_tx) * FeeRate::BROADCAST_MIN;
            // The sender pays original tx fee
            let original_tx_fee = psbt.fee()?;
            let sender_fee = original_tx_fee;
            // The receiver pays the difference
            let receiver_fee = network_fees - sender_fee;
            assert_eq!(payjoin_tx.input.len(), 1);
            assert_eq!(payjoin_tx.output.len(), 3);
            assert_eq!(
                receiver.get_balances()?.mine.untrusted_pending,
                Amount::from_btc(0.9)? - receiver_fee
            );
            assert_eq!(third_party.get_balances()?.mine.untrusted_pending, Amount::from_btc(0.1)?);
            // sender balance is considered "trusted" because all inputs in the transaction were
            // created by their wallet
            assert_eq!(sender.get_balances()?.mine.trusted, Amount::from_btc(49.0)? - sender_fee);
            Ok(())
        }
    }

    fn init_tracing() {
        INIT_TRACING.get_or_init(|| {
            let subscriber = FmtSubscriber::builder()
                .with_env_filter(EnvFilter::from_default_env())
                .with_test_writer()
                .finish();

            tracing::subscriber::set_global_default(subscriber)
                .expect("failed to set global default subscriber");
        });
    }

    fn init_bitcoind_sender_receiver(
        sender_address_type: Option<AddressType>,
        receiver_address_type: Option<AddressType>,
    ) -> Result<(bitcoind::BitcoinD, bitcoincore_rpc::Client, bitcoincore_rpc::Client), BoxError>
    {
        let bitcoind_exe =
            env::var("BITCOIND_EXE").ok().or_else(|| bitcoind::downloaded_exe_path().ok()).unwrap();
        let mut conf = bitcoind::Conf::default();
        conf.view_stdout = log_enabled!(Level::Debug);
        let bitcoind = bitcoind::BitcoinD::with_conf(bitcoind_exe, &conf)?;
        let receiver = bitcoind.create_wallet("receiver")?;
        let receiver_address =
            receiver.get_new_address(None, receiver_address_type)?.assume_checked();
        let sender = bitcoind.create_wallet("sender")?;
        let sender_address = sender.get_new_address(None, sender_address_type)?.assume_checked();
        bitcoind.client.generate_to_address(1, &receiver_address)?;
        bitcoind.client.generate_to_address(101, &sender_address)?;

        assert_eq!(
            Amount::from_btc(50.0)?,
            receiver.get_balances()?.mine.trusted,
            "receiver doesn't own bitcoin"
        );

        assert_eq!(
            Amount::from_btc(50.0)?,
            sender.get_balances()?.mine.trusted,
            "sender doesn't own bitcoin"
        );
        Ok((bitcoind, sender, receiver))
    }

    fn build_original_psbt(
        sender: &bitcoincore_rpc::Client,
        pj_uri: &PjUri,
    ) -> Result<Psbt, BoxError> {
        let mut outputs = HashMap::with_capacity(1);
        outputs.insert(pj_uri.address.to_string(), pj_uri.amount.unwrap_or(Amount::ONE_BTC));
        let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
            lock_unspent: Some(true),
            // The minimum relay feerate ensures that tests fail if the receiver would add inputs/outputs
            // that cannot be covered by the sender's additional fee contributions.
            fee_rate: Some(Amount::from_sat(DEFAULT_MIN_RELAY_TX_FEE.into())),
            ..Default::default()
        };
        let psbt = sender
            .wallet_create_funded_psbt(
                &[], // inputs
                &outputs,
                None, // locktime
                Some(options),
                Some(true), // check that the sender properly clears keypaths
            )?
            .psbt;
        let psbt = sender.wallet_process_psbt(&psbt, None, None, None)?.psbt;
        Ok(Psbt::from_str(&psbt)?)
    }

    // Receiver receive and process original_psbt from a sender
    // In production it it will come in as an HTTP request (over ssl or onion)
    fn handle_v1_pj_request(
        req: Request,
        headers: impl payjoin::receive::v1::Headers,
        receiver: &bitcoincore_rpc::Client,
        custom_outputs: Option<Vec<TxOut>>,
        drain_script: Option<&bitcoin::Script>,
        custom_inputs: Option<Vec<InputPair>>,
    ) -> Result<String, BoxError> {
        // Receiver receive payjoin proposal, IRL it will be an HTTP request (over ssl or onion)
        let proposal = payjoin::receive::v1::UncheckedProposal::from_request(
            req.body.as_slice(),
            req.url.query().unwrap_or(""),
            headers,
        )?;
        let proposal =
            handle_proposal(proposal, receiver, custom_outputs, drain_script, custom_inputs)?;
        assert!(!proposal.is_output_substitution_disabled());
        let psbt = proposal.psbt();
        tracing::debug!("Receiver's Payjoin proposal PSBT: {:#?}", &psbt);
        Ok(psbt.to_string())
    }

    fn handle_proposal(
        proposal: payjoin::receive::v1::UncheckedProposal,
        receiver: &bitcoincore_rpc::Client,
        custom_outputs: Option<Vec<TxOut>>,
        drain_script: Option<&bitcoin::Script>,
        custom_inputs: Option<Vec<InputPair>>,
    ) -> Result<payjoin::receive::v1::PayjoinProposal, BoxError> {
        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

        // Receive Check 1: Can Broadcast
        let proposal = proposal.check_broadcast_suitability(None, |tx| {
            Ok(receiver
                .test_mempool_accept(&[bitcoin::consensus::encode::serialize_hex(&tx)])
                .unwrap()
                .first()
                .unwrap()
                .allowed)
        })?;

        // Receive Check 2: receiver can't sign for proposal inputs
        let proposal = proposal.check_inputs_not_owned(|input| {
            let address = bitcoin::Address::from_script(input, bitcoin::Network::Regtest).unwrap();
            Ok(receiver.get_address_info(&address).unwrap().is_mine.unwrap())
        })?;

        // Receive Check 3: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
        let payjoin = proposal
            .check_no_inputs_seen_before(|_| Ok(false))?
            .identify_receiver_outputs(|output_script| {
                let address =
                    bitcoin::Address::from_script(output_script, bitcoin::Network::Regtest)
                        .unwrap();
                Ok(receiver.get_address_info(&address).unwrap().is_mine.unwrap())
            })?;

        let payjoin = match custom_outputs {
            Some(txos) => payjoin.replace_receiver_outputs(txos, drain_script.unwrap())?,
            None => payjoin.substitute_receiver_script(
                &receiver.get_new_address(None, None)?.assume_checked().script_pubkey(),
            )?,
        }
        .commit_outputs();

        let inputs = match custom_inputs {
            Some(inputs) => inputs,
            None => {
                let candidate_inputs = receiver
                    .list_unspent(None, None, None, None, None)?
                    .into_iter()
                    .map(input_pair_from_list_unspent);
                let selected_input = payjoin
                    .try_preserving_privacy(candidate_inputs)
                    .map_err(|e| format!("Failed to make privacy preserving selection: {:?}", e))?;
                vec![selected_input]
            }
        };
        let payjoin = payjoin
            .contribute_inputs(inputs)
            .map_err(|e| format!("Failed to contribute inputs: {:?}", e))?
            .commit_inputs();

        let payjoin_proposal = payjoin.finalize_proposal(
            |psbt: &Psbt| {
                Ok(receiver
                    .wallet_process_psbt(
                        &psbt.to_string(),
                        None,
                        None,
                        Some(true), // check that the receiver properly clears keypaths
                    )
                    .map(|res: WalletProcessPsbtResult| Psbt::from_str(&res.psbt).unwrap())
                    .unwrap())
            },
            Some(FeeRate::BROADCAST_MIN),
            FeeRate::from_sat_per_vb_unchecked(2),
        )?;
        Ok(payjoin_proposal)
    }

    fn extract_pj_tx(
        sender: &bitcoincore_rpc::Client,
        psbt: Psbt,
    ) -> Result<bitcoin::Transaction, Box<dyn std::error::Error>> {
        let payjoin_psbt = sender.wallet_process_psbt(&psbt.to_string(), None, None, None)?.psbt;
        let payjoin_psbt = sender.finalize_psbt(&payjoin_psbt, Some(false))?.psbt.unwrap();
        let payjoin_psbt = Psbt::from_str(&payjoin_psbt)?;
        tracing::debug!("Sender's Payjoin PSBT: {:#?}", payjoin_psbt);

        Ok(payjoin_psbt.extract_tx()?)
    }

    /// Simplified input weight predictions for a fully-signed transaction
    fn predicted_tx_weight(tx: &bitcoin::Transaction) -> Weight {
        let input_weight_predictions = tx.input.iter().map(|txin| {
            // See https://bitcoin.stackexchange.com/a/107873
            match (txin.script_sig.is_empty(), txin.witness.is_empty()) {
                // witness is empty: legacy input
                (false, true) => InputWeightPrediction::P2PKH_COMPRESSED_MAX,
                // script sig is empty: native segwit input
                (true, false) => match txin.witness.len() {
                    // <signature>
                    1 => InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH,
                    // <signature> <public_key>
                    2 => InputWeightPrediction::P2WPKH_MAX,
                    _ => panic!("unsupported witness"),
                },
                // neither are empty: nested segwit (p2wpkh-in-p2sh) input
                (false, false) => InputWeightPrediction::from_slice(23, &[72, 33]),
                _ => panic!("one of script_sig or witness should be non-empty"),
            }
        });
        bitcoin::transaction::predict_weight(input_weight_predictions, tx.script_pubkey_lens())
    }

    fn input_pair_from_list_unspent(
        utxo: bitcoind::bitcoincore_rpc::bitcoincore_rpc_json::ListUnspentResultEntry,
    ) -> InputPair {
        let psbtin = PsbtInput {
            // NOTE: non_witness_utxo is not necessary because bitcoin-cli always supplies
            // witness_utxo, even for non-witness inputs
            witness_utxo: Some(TxOut {
                value: utxo.amount,
                script_pubkey: utxo.script_pub_key.clone(),
            }),
            redeem_script: utxo.redeem_script.clone(),
            witness_script: utxo.witness_script.clone(),
            ..Default::default()
        };
        let txin = TxIn {
            previous_output: OutPoint { txid: utxo.txid, vout: utxo.vout },
            ..Default::default()
        };
        InputPair::new(txin, psbtin).expect("Input pair should be valid")
    }

    struct HeaderMock(HashMap<String, String>);

    impl payjoin::receive::v1::Headers for HeaderMock {
        fn get_header(&self, key: &str) -> Option<&str> { self.0.get(key).map(|e| e.as_str()) }
    }

    impl HeaderMock {
        fn new(body: &[u8], content_type: &str) -> HeaderMock {
            let mut h = HashMap::new();
            h.insert("content-type".to_string(), content_type.to_string());
            h.insert("content-length".to_string(), body.len().to_string());
            HeaderMock(h)
        }
    }
}
