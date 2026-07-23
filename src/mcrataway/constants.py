"""Constants, enums, and fixed values used across the scanner."""

from enum import IntEnum, StrEnum
from pathlib import Path

# Scanner metadata
SCANNER_NAME = "mcrataway"
SCANNER_VERSION = "1.0.0"

# Default server bind
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765

# User config directory
CONFIG_DIR = Path.home() / ".mcrataway"
QUARANTINE_DIR = CONFIG_DIR / "quarantine"
TOKEN_FILE = CONFIG_DIR / "token"
CONFIG_FILE = CONFIG_DIR / "config.yaml"

# Java bytecode magic
JAVA_CLASS_MAGIC = b"\xCA\xFE\xBA\xBE"

# Archive extensions to scan
ARCHIVE_EXTENSIONS = {".jar", ".zip", ".mcworld", ".mcpack"}

# Script extensions to scan
SCRIPT_EXTENSIONS = {".js", ".ts", ".mcfunction", ".lua"}

# Config extensions to scan
CONFIG_EXTENSIONS = {".json", ".toml", ".yml", ".yaml", ".mcmeta", ".txt"}

# Subfolders to scan within each Minecraft root
SCAN_SUBDIRS = {
    "mods",
    "resourcepacks",
    "datapacks",
    "shaderpacks",
    "kubejs",
    "scripts",
    "config",
    "saves",
}


class Severity(IntEnum):
    """Threat severity levels."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Verdict(StrEnum):
    """Scan verdict for an artifact."""

    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class JobStatus(StrEnum):
    """Scan job lifecycle states."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


# Java VM opcode values (subset needed for analysis)
OPCODE_NAMES = {
    0: "nop",
    1: "aconst_null",
    2: "iconst_m1",
    3: "iconst_0",
    4: "iconst_1",
    5: "iconst_2",
    6: "iconst_3",
    7: "iconst_4",
    8: "iconst_5",
    9: "lconst_0",
    10: "lconst_1",
    11: "fconst_0",
    12: "fconst_1",
    13: "fconst_2",
    14: "dconst_0",
    15: "dconst_1",
    16: "bipush",
    17: "sipush",
    18: "ldc",
    19: "ldc_w",
    20: "ldc2_w",
    21: "iload",
    22: "lload",
    23: "fload",
    24: "dload",
    25: "aload",
    26: "iload_0",
    27: "iload_1",
    28: "iload_2",
    29: "iload_3",
    30: "lload_0",
    31: "lload_1",
    32: "lload_2",
    33: "lload_3",
    34: "fload_0",
    35: "fload_1",
    36: "fload_2",
    37: "fload_3",
    38: "dload_0",
    39: "dload_1",
    40: "dload_2",
    41: "dload_3",
    42: "aload_0",
    43: "aload_1",
    44: "aload_2",
    45: "aload_3",
    46: "iaload",
    47: "laload",
    48: "faload",
    49: "daload",
    50: "aaload",
    51: "baload",
    52: "caload",
    53: "saload",
    54: "istore",
    55: "lstore",
    56: "fstore",
    57: "dstore",
    58: "astore",
    59: "istore_0",
    60: "istore_1",
    61: "istore_2",
    62: "istore_3",
    63: "lstore_0",
    64: "lstore_1",
    65: "lstore_2",
    66: "lstore_3",
    67: "fstore_0",
    68: "fstore_1",
    69: "fstore_2",
    70: "fstore_3",
    71: "dstore_0",
    72: "dstore_1",
    73: "dstore_2",
    74: "dstore_3",
    75: "astore_0",
    76: "astore_1",
    77: "astore_2",
    78: "astore_3",
    79: "iastore",
    80: "lastore",
    81: "fastore",
    82: "dastore",
    83: "aastore",
    84: "bastore",
    85: "castore",
    86: "sastore",
    87: "pop",
    88: "pop2",
    89: "dup",
    90: "dup_x1",
    91: "dup_x2",
    92: "dup2",
    93: "dup2_x1",
    94: "dup2_x2",
    95: "swap",
    96: "iadd",
    97: "ladd",
    98: "fadd",
    99: "dadd",
    100: "isub",
    101: "lsub",
    102: "fsub",
    103: "dsub",
    104: "imul",
    105: "lmul",
    106: "fmul",
    107: "dmul",
    108: "idiv",
    109: "ldiv",
    110: "fdiv",
    111: "ddiv",
    112: "irem",
    113: "lrem",
    114: "frem",
    115: "drem",
    116: "ineg",
    117: "lneg",
    118: "fneg",
    119: "dneg",
    120: "ishl",
    121: "lshl",
    122: "ishr",
    123: "lshr",
    124: "iushr",
    125: "lushr",
    126: "iand",
    127: "land",
    128: "ior",
    129: "lor",
    130: "ixor",
    131: "lxor",
    132: "iinc",
    133: "i2l",
    134: "i2f",
    135: "i2d",
    136: "l2i",
    137: "l2f",
    138: "l2d",
    139: "f2i",
    140: "f2l",
    141: "f2d",
    142: "d2i",
    143: "d2l",
    144: "d2f",
    145: "i2b",
    146: "i2c",
    147: "i2s",
    148: "lcmp",
    149: "fcmpl",
    150: "fcmpg",
    151: "dcmpl",
    152: "dcmpg",
    153: "ifeq",
    154: "ifne",
    155: "iflt",
    156: "ifge",
    157: "ifgt",
    158: "ifle",
    159: "if_icmpeq",
    160: "if_icmpne",
    161: "if_icmplt",
    162: "if_icmpge",
    163: "if_icmpgt",
    164: "if_icmple",
    165: "if_acmpeq",
    166: "if_acmpne",
    167: "goto",
    168: "jsr",
    169: "ret",
    170: "tableswitch",
    171: "lookupswitch",
    172: "ireturn",
    173: "lreturn",
    174: "freturn",
    175: "dreturn",
    176: "areturn",
    177: "return",
    178: "getstatic",
    179: "putstatic",
    180: "getfield",
    181: "putfield",
    182: "invokevirtual",
    183: "invokespecial",
    184: "invokestatic",
    185: "invokeinterface",
    186: "invokedynamic",
    187: "new",
    188: "newarray",
    189: "anewarray",
    190: "arraylength",
    191: "athrow",
    192: "checkcast",
    193: "instanceof",
    194: "monitorenter",
    195: "monitorexit",
    196: "wide",
    197: "multianewarray",
    198: "ifnull",
    199: "ifnonnull",
    200: "goto_w",
    201: "jsr_w",
}

# Invoke opcodes
INVOKE_OPCODES = {182, 183, 184, 185, 186}

# Array type codes for newarray
ARRAY_TYPE_CODES = {
    4: "boolean",
    5: "char",
    6: "float",
    7: "double",
    8: "byte",
    9: "short",
    10: "int",
    11: "long",
}

# Access flags
ACC_PUBLIC = 0x0001
ACC_PRIVATE = 0x0002
ACC_PROTECTED = 0x0004
ACC_STATIC = 0x0008
ACC_FINAL = 0x0010
ACC_SYNCHRONIZED = 0x0020
ACC_VOLATILE = 0x0040
ACC_BRIDGE = 0x0040
ACC_TRANSIENT = 0x0080
ACC_VARARGS = 0x0080
ACC_NATIVE = 0x0100
ACC_INTERFACE = 0x0200
ACC_ABSTRACT = 0x0400
ACC_STRICT = 0x0800
ACC_SYNTHETIC = 0x1000
ACC_ANNOTATION = 0x2000
ACC_ENUM = 0x4000
ACC_MODULE = 0x8000

# Constant pool tags
CONSTANT_Utf8 = 1
CONSTANT_Integer = 3
CONSTANT_Float = 4
CONSTANT_Long = 5
CONSTANT_Double = 6
CONSTANT_Class = 7
CONSTANT_String = 8
CONSTANT_Fieldref = 9
CONSTANT_Methodref = 10
CONSTANT_InterfaceMethodref = 11
CONSTANT_NameAndType = 12
CONSTANT_MethodHandle = 15
CONSTANT_MethodType = 16
CONSTANT_InvokeDynamic = 18
