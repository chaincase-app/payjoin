use bitcoincore_rpc::jsonrpc::serde_json;
use payjoin::receive::v2::ActiveSession;
use payjoin::send::RequestContext;
use sled::{IVec, Tree};
use url::Url;

use super::*;

impl Database {
    pub(crate) fn insert_recv_session(&self, session: ActiveSession) -> Result<()> {
        let recv_tree = self.0.open_tree("recv_sessions")?;
        let key = &session.public_key().serialize();
        let value = serde_json::to_string(&session).map_err(Error::Serialize)?;
        recv_tree.insert(key.as_slice(), IVec::from(value.as_str()))?;
        recv_tree.flush()?;
        Ok(())
    }

    pub(crate) fn get_recv_sessions(&self) -> Result<Vec<ActiveSession>> {
        let recv_tree = self.0.open_tree("recv_sessions")?;
        let mut sessions = Vec::new();
        for item in recv_tree.iter() {
            let (_, value) = item?;
            let session: ActiveSession =
                serde_json::from_slice(&value).map_err(Error::Deserialize)?;
            sessions.push(session);
        }
        Ok(sessions)
    }

    pub(crate) fn clear_recv_session(&self) -> Result<()> {
        let recv_tree: Tree = self.0.open_tree("recv_sessions")?;
        recv_tree.clear()?;
        recv_tree.flush()?;
        Ok(())
    }

    pub(crate) fn insert_send_session(
        &self,
        session: &mut RequestContext,
        pj_url: &Url,
    ) -> Result<()> {
        let send_tree: Tree = self.0.open_tree("send_sessions")?;
        let value = serde_json::to_string(session).map_err(Error::Serialize)?;
        send_tree.insert(pj_url.to_string(), IVec::from(value.as_str()))?;
        send_tree.flush()?;
        Ok(())
    }

    pub(crate) fn get_send_sessions(&self) -> Result<Vec<RequestContext>> {
        let send_tree: Tree = self.0.open_tree("send_sessions")?;
        let mut sessions = Vec::new();
        for item in send_tree.iter() {
            let (_, value) = item?;
            let session: RequestContext =
                serde_json::from_slice(&value).map_err(Error::Deserialize)?;
            sessions.push(session);
        }
        Ok(sessions)
    }

    pub(crate) fn get_send_session(&self, pj_url: &Url) -> Result<Option<RequestContext>> {
        let send_tree = self.0.open_tree("send_sessions")?;
        if let Some(val) = send_tree.get(pj_url.to_string())? {
            let session: RequestContext =
                serde_json::from_slice(&val).map_err(Error::Deserialize)?;
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn clear_send_session(&self, pj_url: &Url) -> Result<()> {
        let send_tree: Tree = self.0.open_tree("send_sessions")?;
        send_tree.remove(pj_url.to_string())?;
        send_tree.flush()?;
        Ok(())
    }
}
