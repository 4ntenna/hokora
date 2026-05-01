# SPDX-FileCopyrightText: 2026 4ntenna <4ntenn@proton.me>, The Hokora Project
# SPDX-License-Identifier: AGPL-3.0-only
"""Protocol constants, message types, permissions, sync actions."""

# --- Message Types ---
MSG_TEXT = 0x01
MSG_MEDIA = 0x02
MSG_SYSTEM = 0x03
MSG_REACTION = 0x04
MSG_THREAD_REPLY = 0x05
MSG_DELETE = 0x06
MSG_PIN = 0x07
MSG_EDIT = 0x08

VALID_MESSAGE_TYPES = {
    MSG_TEXT,
    MSG_MEDIA,
    MSG_SYSTEM,
    MSG_REACTION,
    MSG_THREAD_REPLY,
    MSG_DELETE,
    MSG_PIN,
    MSG_EDIT,
}

MESSAGE_TYPE_NAMES = {
    MSG_TEXT: "text",
    MSG_MEDIA: "media",
    MSG_SYSTEM: "system",
    MSG_REACTION: "reaction",
    MSG_THREAD_REPLY: "thread_reply",
    MSG_DELETE: "delete",
    MSG_PIN: "pin",
    MSG_EDIT: "edit",
}

# --- Sync Actions ---
SYNC_HISTORY = 0x01
SYNC_SUBSCRIBE_LIVE = 0x02
SYNC_UNSUBSCRIBE = 0x03
SYNC_NODE_META = 0x04
SYNC_THREAD = 0x05
SYNC_GET_PINS = 0x06
SYNC_SEARCH = 0x07
SYNC_GET_MEMBER_LIST = 0x08
SYNC_FETCH_MEDIA = 0x09
SYNC_REDEEM_INVITE = 0x0A
SYNC_FEDERATION_HANDSHAKE = 0x0B
SYNC_PUSH_MESSAGES = 0x0C
SYNC_REQUEST_SEALED_KEY = 0x0D
# Read-only listing of the daemon's currently configured RNS interfaces
# ("seeds"). Mutation is CLI-only via ``hokora seed add/remove``; this
# action exists solely so the TUI can render the canonical seed list
# without re-parsing the RNS config on the client side.
SYNC_LIST_SEEDS = 0x23

SYNC_ACTION_NAMES = {
    SYNC_HISTORY: "sync_history",
    SYNC_SUBSCRIBE_LIVE: "subscribe_live",
    SYNC_UNSUBSCRIBE: "unsubscribe",
    SYNC_NODE_META: "sync_node_meta",
    SYNC_THREAD: "sync_thread",
    SYNC_GET_PINS: "get_pins",
    SYNC_SEARCH: "search",
    SYNC_GET_MEMBER_LIST: "get_member_list",
    SYNC_FETCH_MEDIA: "fetch_media",
    SYNC_REDEEM_INVITE: "redeem_invite",
    SYNC_FEDERATION_HANDSHAKE: "federation_handshake",
    SYNC_PUSH_MESSAGES: "push_messages",
    SYNC_REQUEST_SEALED_KEY: "request_sealed_key",
    SYNC_LIST_SEEDS: "list_seeds",
}

# --- Permission Flags (32-bit, 14 flags per design doc) ---
PERM_SEND_MESSAGES = 0x0001
PERM_SEND_MEDIA = 0x0002
PERM_CREATE_THREADS = 0x0004
PERM_USE_MENTIONS = 0x0008
PERM_MENTION_EVERYONE = 0x0010
PERM_ADD_REACTIONS = 0x0020
PERM_READ_HISTORY = 0x0040
PERM_DELETE_OWN = 0x0080
PERM_DELETE_OTHERS = 0x0100
PERM_PIN_MESSAGES = 0x0200
PERM_MANAGE_CHANNELS = 0x0400
PERM_MANAGE_ROLES = 0x0800
PERM_MANAGE_MEMBERS = 0x1000
PERM_BAN_IDENTITIES = 0x2000
PERM_VIEW_AUDIT_LOG = 0x4000
PERM_EDIT_OWN = 0x8000

# All permissions set
PERM_ALL = 0xFFFF

# Default everyone permissions
PERM_EVERYONE_DEFAULT = (
    PERM_SEND_MESSAGES
    | PERM_SEND_MEDIA
    | PERM_CREATE_THREADS
    | PERM_USE_MENTIONS
    | PERM_ADD_REACTIONS
    | PERM_READ_HISTORY
    | PERM_DELETE_OWN
    | PERM_EDIT_OWN
)

# Node owner gets all permissions
PERM_NODE_OWNER = PERM_ALL

# --- Access Modes ---
ACCESS_PUBLIC = "public"
ACCESS_WRITE_RESTRICTED = "write_restricted"
ACCESS_PRIVATE = "private"

# --- Protocol Limits ---
NONCE_SIZE = 16  # bytes
MAX_SYNC_LIMIT = 100
DEFAULT_SYNC_LIMIT = 50
CLOCK_DRIFT_TOLERANCE = 300  # 5 minutes in seconds
MAX_EDIT_CHAIN_LENGTH = 50
MAX_REACTIONS_PER_MESSAGE = 20
MAX_MENTIONS_PER_MESSAGE = 25
MAX_MESSAGE_BODY_SIZE = 32000  # bytes
MAX_DISPLAY_NAME_LENGTH = 64
MAX_CHANNEL_NAME_LENGTH = 64
MAX_CHANNEL_DESCRIPTION_LENGTH = 512

# Sequence integrity thresholds
SEQ_GAP_NORMAL = 5
SEQ_GAP_WARNING = 5

# Invite defaults
INVITE_DEFAULT_EXPIRY_HOURS = 72
INVITE_DEFAULT_MAX_USES = 1
INVITE_TOKEN_SIZE = 16  # 128-bit
INVITE_RATE_LIMIT_WINDOW = 600  # 10 minutes
INVITE_RATE_LIMIT_MAX = 5
INVITE_FAILURE_BLOCK_THRESHOLD = 3
INVITE_FAILURE_BLOCK_DURATION = 3600  # 1 hour

# Live subscription limits
MAX_SUBSCRIBERS_PER_CHANNEL = 100
MAX_TOTAL_SUBSCRIBERS = 500

# Resource-bounding caps (prevent unbounded dict growth)
MAX_LOCK_ENTRIES = 10_000
MAX_RATE_LIMIT_BUCKETS = 10_000
MAX_PENDING_CHALLENGES = 10_000
MAX_INVITE_RATE_ENTRIES = 10_000

# Rate limiting
DEFAULT_RATE_LIMIT_TOKENS = 10
DEFAULT_RATE_LIMIT_REFILL = 1.0  # tokens per second

# Media
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5MB default
MAX_UPLOAD_BYTES_LIMIT = 50 * 1024 * 1024  # 50MB hard limit
MAX_STORAGE_BYTES = 1024 * 1024 * 1024  # 1GB default
MAX_GLOBAL_STORAGE_BYTES = 10 * 1024 * 1024 * 1024  # 10GB default
MAX_THUMBNAIL_BYTES = 32 * 1024  # 32KB
MAX_AVATAR_BYTES = 32 * 1024

# Sealed channels
SEALED_CHANNEL_MAX_MEMBERS = 50
SEALED_KEY_ROTATION_DAYS = 30

# Wire protocol
WIRE_VERSION = 1

# Built-in role names
ROLE_NODE_OWNER = "node_owner"
ROLE_CHANNEL_OWNER = "channel_owner"
ROLE_EVERYONE = "everyone"
ROLE_MEMBER = "member"

# Destination aspect
DESTINATION_ASPECT = "hokora"

# --- CDSP (Client-Declared Sync Profiles) ---
CDSP_VERSION = 1

# Sync profile identifiers (uint8)
CDSP_PROFILE_FULL = 0x01
CDSP_PROFILE_PRIORITIZED = 0x02
CDSP_PROFILE_MINIMAL = 0x03
CDSP_PROFILE_BATCHED = 0x04

# Session states
CDSP_STATE_INIT = "init"
CDSP_STATE_ACTIVE = "active"
CDSP_STATE_SUSPENDED = "suspended"
CDSP_STATE_CLOSED = "closed"

# CDSP sync action codes (extend existing 0x01-0x0D range)
SYNC_CDSP_SESSION_INIT = 0x0E
SYNC_CDSP_SESSION_ACK = 0x0F
SYNC_CDSP_PROFILE_UPDATE = 0x10
SYNC_CDSP_SESSION_REJECT = 0x11

# Invite management (TUI → daemon)
SYNC_CREATE_INVITE = 0x12
SYNC_LIST_INVITES = 0x13

# Deferred live-push event. Not a client-initiated action — used internally
# as the ``sync_action`` code on DeferredSyncItem rows that hold a live push
# event (message / message_updated / reaction / etc.) that couldn't be
# delivered to a subscriber whose Link had died. On CDSP session resume the
# daemon flushes these back to the client in FIFO order; the client replays
# them as if they had arrived live. Transport-agnostic — the queuing logic
# doesn't care whether the drop was TCP, I2P, LoRa, or future transports.
SYNC_LIVE_EVENT = 0x30

# CDSP defaults
CDSP_SESSION_TIMEOUT = 3600
CDSP_INIT_TIMEOUT = 5
CDSP_DEFERRED_QUEUE_LIMIT = 1000
CDSP_RESUME_TOKEN_SIZE = 16

# Per-profile sync limits
# --- Forward Secrecy Epoch Protocol ---
EPOCH_ROTATE = 0x20
EPOCH_ROTATE_ACK = 0x21
EPOCH_DATA = 0x22

EPOCH_DEFAULT_DURATION = 3600  # 1 hour
EPOCH_MIN_DURATION = 300  # 5 minutes
EPOCH_MAX_DURATION = 86400  # 24 hours
EPOCH_MAX_RETRIES = 3
EPOCH_INITIAL_BACKOFF = 30
EPOCH_NONCE_OVERFLOW = 2**63
EPOCH_ROTATE_TIMEOUT = 30  # seconds to wait for Ack

CDSP_PROFILE_LIMITS = {
    CDSP_PROFILE_FULL: {
        "max_sync_limit": 100,
        "default_sync_limit": 50,
        "search_limit": 100,
        "media_fetch": True,
        "live_push": True,
        "live_batch_window": 0,
        "include_metadata": True,
    },
    CDSP_PROFILE_PRIORITIZED: {
        "max_sync_limit": 20,
        "default_sync_limit": 10,
        "search_limit": 10,
        "media_fetch": False,
        "live_push": True,
        "live_batch_window": 0,
        "include_metadata": False,
        "history_direction": "backward",
    },
    CDSP_PROFILE_MINIMAL: {
        "max_sync_limit": 5,
        "default_sync_limit": 3,
        "search_limit": 0,
        "media_fetch": False,
        "live_push": False,
        "live_batch_window": 0,
        "include_metadata": False,
    },
    CDSP_PROFILE_BATCHED: {
        "max_sync_limit": 50,
        "default_sync_limit": 25,
        "search_limit": 20,
        "media_fetch": True,
        "live_push": True,
        "live_batch_window": 30.0,
        "include_metadata": True,
    },
}

# --- Deferred sealed-key distribution ---
# Bound on auto-retry attempts for a queued sealed-key distribution. After
# this many failures the entry is preserved (operator visibility via
# ``hokora role pending``) but no longer auto-retried on each announce — a
# stuck entry usually means a bad identity hash or a peer that genuinely
# never announces, both of which are operator concerns.
MAX_PENDING_DISTRIBUTION_RETRIES = 5
