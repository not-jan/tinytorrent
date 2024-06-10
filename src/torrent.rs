use serde_bytes::ByteBuf;
use serde_derive::{Deserialize, Serialize};
use sha1::{Sha1, Digest};
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize)]
pub struct Info {
    #[serde(rename = "piece length")]
    pub piece_length: u64,
    pub pieces: ByteBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private: Option<i64>,
    pub name: String,
    #[serde(flatten)]
    pub mode: FileMode,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FileMode {
    MultipleFiles {
         files: Vec<File>,
    },
    SingleFile {
         length: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
         md5sum: Option<ByteBuf>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct File {
    pub length: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5sum: Option<ByteBuf>,
    pub path: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MetaInfo {
    pub info: Info,
    pub announce: String,
    #[serde(rename = "announce-list", skip_serializing_if = "Option::is_none")]
    pub announce_list: Option<Vec<Vec<String>>>,
    #[serde(rename = "creation date", skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(rename = "created by", skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

impl MetaInfo {
    pub fn info_hash(&self) -> Result<[u8; 20]> {
        let info = serde_bencoded::to_vec(&self.info)?;
        let mut hasher = Sha1::new();
        hasher.update(info);
        let hash = hasher.finalize();
        Ok(hash.into())
    }

    pub fn as_magnet_link(&self) -> Result<String> {
        let info_hash = self.info_hash()?;
        let mut hex_result = String::with_capacity(40);
        for byte in info_hash {
            hex_result.push_str(&format!("{:02x}", byte));
        }


        let url: String = url::form_urlencoded::byte_serialize(self.announce.as_bytes()).collect();
        Ok(format!("magnet:?xt=urn:btih:{}&dn={}&tr={}", hex_result, self.info.name, url))
    }
}