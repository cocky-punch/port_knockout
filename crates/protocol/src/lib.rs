use std::str;

const MAGIC: &[u8; 4] = b"VPA1";
const VERSION: u8 = 1;

const OPEN: u8 = 1;
const END_SESSION: u8 = 2;
const RESPONSE: u8 = 3;

const DEVICE_ID_LENGTH: usize = 32;
const MAC_LENGTH: usize = 32;

const REQUEST_LENGTH: usize = 4 + 1 + 1 + DEVICE_ID_LENGTH + 8 + 1 + MAC_LENGTH;
const RESPONSE_LENGTH: usize = 4 + 1 + 1 + 1 + 8 + 4 + MAC_LENGTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Vpn = 1,
    Ssh = 2,
    Admin = 3,
}

impl TryFrom<u8> for Profile {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Vpn),
            2 => Ok(Self::Ssh),
            3 => Ok(Self::Admin),
            _ => Err(ProtocolError::InvalidProfile),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Open,
    EndSession,
}

impl RequestKind {
    fn as_byte(self) -> u8 {
        match self {
            Self::Open => OPEN,
            Self::EndSession => END_SESSION,
        }
    }

    fn from_byte(value: u8) -> Result<Self, ProtocolError> {
        match value {
            OPEN => Ok(Self::Open),
            END_SESSION => Ok(Self::EndSession),
            _ => Err(ProtocolError::InvalidMessageType),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStatus {
    Ok,
    Err,
}

impl ResponseStatus {
    fn as_byte(self) -> u8 {
        match self {
            Self::Ok => 1,
            Self::Err => 2,
        }
    }

    fn from_byte(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Ok),
            2 => Ok(Self::Err),
            _ => Err(ProtocolError::InvalidStatus),
        }
    }
}

#[derive(Debug)]
pub struct Request {
    pub kind: RequestKind,
    pub device_id: String,
    pub timestamp: u64,
    pub profile: Profile,
    pub mac: [u8; MAC_LENGTH],
}

impl Request {
    pub fn authentication_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.device_id.is_empty()
            || self.device_id.len() > DEVICE_ID_LENGTH
            || self.device_id.as_bytes().contains(&0)
        {
            return Err(ProtocolError::InvalidDeviceId);
        }

        let mut bytes = Vec::with_capacity(REQUEST_LENGTH - MAC_LENGTH);
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.push(self.kind.as_byte());

        let mut encoded_device_id = [0u8; DEVICE_ID_LENGTH];
        encoded_device_id[..self.device_id.len()].copy_from_slice(self.device_id.as_bytes());

        bytes.extend_from_slice(&encoded_device_id);
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.push(self.profile as u8);

        Ok(bytes)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut bytes = self.authentication_bytes()?;
        bytes.extend_from_slice(&self.mac);
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != REQUEST_LENGTH {
            return Err(ProtocolError::InvalidLength);
        }

        validate_header(bytes)?;

        let kind = RequestKind::from_byte(bytes[5])?;
        let device_id_bytes = &bytes[6..6 + DEVICE_ID_LENGTH];
        let device_id_end = device_id_bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(DEVICE_ID_LENGTH);

        if device_id_end == 0
            || device_id_bytes[device_id_end..]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(ProtocolError::InvalidDeviceId);
        }

        let device_id = str::from_utf8(&device_id_bytes[..device_id_end])
            .map_err(|_| ProtocolError::InvalidDeviceId)?
            .to_owned();

        let timestamp_start = 6 + DEVICE_ID_LENGTH;
        let timestamp = u64::from_be_bytes(
            bytes[timestamp_start..timestamp_start + 8]
                .try_into()
                .map_err(|_| ProtocolError::InvalidLength)?,
        );

        let profile = Profile::try_from(bytes[timestamp_start + 8])?;

        let mac_start = REQUEST_LENGTH - MAC_LENGTH;
        let mut mac = [0u8; MAC_LENGTH];
        mac.copy_from_slice(&bytes[mac_start..]);

        Ok(Self {
            kind,
            device_id,
            timestamp,
            profile,
            mac,
        })
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: ResponseStatus,
    pub timestamp: u64,
    pub lease_in_seconds: u32,
    pub mac: [u8; MAC_LENGTH],
}

impl Response {
    pub fn authentication_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RESPONSE_LENGTH - MAC_LENGTH);
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.push(RESPONSE);
        bytes.push(self.status.as_byte());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.lease_in_seconds.to_be_bytes());
        bytes
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.authentication_bytes();
        bytes.extend_from_slice(&self.mac);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != RESPONSE_LENGTH {
            return Err(ProtocolError::InvalidLength);
        }

        validate_header(bytes)?;

        if bytes[5] != RESPONSE {
            return Err(ProtocolError::InvalidMessageType);
        }

        let status = ResponseStatus::from_byte(bytes[6])?;
        let timestamp = u64::from_be_bytes(
            bytes[7..15]
                .try_into()
                .map_err(|_| ProtocolError::InvalidLength)?,
        );

        let lease_in_seconds = u32::from_be_bytes(
            bytes[15..19]
                .try_into()
                .map_err(|_| ProtocolError::InvalidLength)?,
        );

        let mut mac = [0u8; MAC_LENGTH];
        mac.copy_from_slice(&bytes[19..]);

        Ok(Self {
            status,
            timestamp,
            lease_in_seconds,
            mac,
        })
    }
}

fn validate_header(bytes: &[u8]) -> Result<(), ProtocolError> {
    if &bytes[..4] != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }

    if bytes[4] != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }

    Ok(())
}

#[derive(Debug)]
pub enum ProtocolError {
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    InvalidMessageType,
    InvalidDeviceId,
    InvalidProfile,
    InvalidStatus,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLength => "invalid packet length",
            Self::InvalidMagic => "invalid packet magic",
            Self::UnsupportedVersion => "unsupported protocol version",
            Self::InvalidMessageType => "invalid message type",
            Self::InvalidDeviceId => "invalid device ID",
            Self::InvalidProfile => "invalid profile",
            Self::InvalidStatus => "invalid response status",
        };

        formatter.write_str(message)
    }
}

impl std::error::Error for ProtocolError {}
