//! Frozen published Astra CLI 0.2.10 catalog decoder.
//!
//! Source: crates/services/src/models.rs at 5aacae0d399906958f0c93f605a8c68641ab9a7b.
//! Declarations below are copied without methods. Do not import current wire
//! types or update this fixture to follow a newer producer.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThinkingCapability {
    /// Model supports Normal (off) and Thinking modes — suppression works.
    /// Adaptive picker: Normal / Thinking (Low) / Thinking (High) / Thinking (Max).
    /// Examples: Bedrock Claude, DashScope Qwen-Plus, GLM-5.1.
    Both,
    /// Model always thinks but supports provider-specific effort control.
    /// Cannot be turned off completely — no "Normal" option.
    /// Adaptive picker: Thinking (Low) / Thinking (High) / Thinking (Max).
    /// Examples: DeepSeek V4.
    EffortOnly,
    /// Model always thinks, no control at all.
    /// No picker shown.
    /// Examples: MiniMax M2.5.
    NativeOnly,
    /// Model does not support thinking.
    /// No picker shown.
    /// Examples: qwen-flash, qwen2.5-3b-instruct.
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelAccessKind {
    AstraCloud,
    CloudByok,
    Workspace,
    ThisDevice,
    SelfHosted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelExecutionPlacement {
    Server,
    Edge,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelListCursor {
    pub provider: String,
    pub model_name: String,
    pub model_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ModelListItemResponse {
    pub offering_id: String,
    pub access_id: String,
    pub access_kind: ModelAccessKind,
    pub access_label: String,
    pub execution_placement: ModelExecutionPlacement,
    pub name: String,
    pub provider: String,
    pub description: Option<String>,
    pub is_active: bool,
    pub context_window: i32,
    pub max_completion_tokens: Option<i32>,
    pub architecture: Option<String>,
    pub thinking_capability: Option<ThinkingCapability>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelListPageResponse {
    pub items: Vec<ModelListItemResponse>,
    pub next_cursor: Option<ModelListCursor>,
    pub limit: u32,
    pub total: u32,
    pub catalog_revision: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelAccessStatus {
    SettingUp,
    Ready,
    Degraded,
    ActionRequired,
    Unavailable,
    Disabled,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelAccessReason {
    Provisioning,
    NoEligibleOfferings,
    ReauthenticationRequired,
    BillingActionRequired,
    ConnectionDegraded,
    ConnectionUnavailable,
    DeviceOffline,
    PolicyDisabled,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelAccessAction {
    ContactAdministrator,
    ReconnectDevice,
    ConfigureDeviceModels,
    ConfigureCloudByokModels,
    Reauthenticate,
    ManageBilling,
    Retry,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelAccessViewResponse {
    pub id: String,
    pub kind: ModelAccessKind,
    pub label: String,
    pub execution_placement: ModelExecutionPlacement,
    pub status: ModelAccessStatus,
    pub reason: Option<ModelAccessReason>,
    pub usable: bool,
    pub retry_after_seconds: Option<u32>,
    pub available_model_count: u32,
    pub actions: Vec<ModelAccessAction>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelDefaultSource {
    Astra,
    ExternalProvider,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelDefaultScope {
    EffectiveCatalog,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelDefaultInvalidReason {
    InvalidOfferingId,
    NotEffectiveOffering,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModelDefaultResolution {
    Selected {
        offering_id: String,
        source: ModelDefaultSource,
        scope: ModelDefaultScope,
    },
    Missing,
    Invalid {
        reason: ModelDefaultInvalidReason,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ModelAccessProjectionResponse {
    pub accesses: Vec<ModelAccessViewResponse>,
    pub offerings: Vec<ModelListItemResponse>,
    pub default_offering_id: Option<String>,
    /// The Astra-owned result of resolving a default against this effective
    /// catalog.  Clients must not infer a replacement default when this is
    /// `invalid`; the listed Offerings remain available for an explicit user
    /// choice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_resolution: Option<ModelDefaultResolution>,
    pub next_cursor: Option<ModelListCursor>,
    /// Requested page size after server-side clamping.
    pub limit: u32,
    /// Number of effective Offerings in the complete catalog, not this page.
    pub total: u32,
    pub catalog_revision: String,
    pub observed_at: String,
}
