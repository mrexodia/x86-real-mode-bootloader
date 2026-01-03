"""
ctypes structure definitions and metaclass for the emulator
"""

import re
import ctypes
from typing import Optional, Tuple, Annotated, get_args, get_origin, Any, List, Protocol

# =============================================================================
# Type Hints
# =============================================================================

class c_array(Protocol):
    """Type hint for ctypes arrays"""
    def __getitem__(self, index: int) -> int: ...
    def __setitem__(self, index: int, value: int) -> None: ...
    def __len__(self) -> int: ...
    def __iter__(self): ...

# =============================================================================
# Metaclass for ctypes structures with annotation support
# =============================================================================

class _CStructMeta(type(ctypes.LittleEndianStructure)):
    """Metaclass for ctypes structures with annotation support and comment extraction"""

    def __new__(mcs, name, bases, namespace):
        if "__annotations__" in namespace:
            fields = []
            comments = {}
            field_annotations = {}  # field_name -> [extra args from Annotated]
            field_offsets = {}      # field_name -> (offset, size)
            current_offset = 0

            # Build fields from annotations
            for field_name, annotation in namespace["__annotations__"].items():
                # Handle Annotated types
                origin = get_origin(annotation)
                if origin is Annotated:
                    args = get_args(annotation)
                    ctypes_type = args[1]  # The actual ctypes type
                    extra_args = list(args[2:]) if len(args) > 2 else []  # Everything after the ctype

                    field_size = ctypes.sizeof(ctypes_type)
                    fields.append((field_name, ctypes_type))

                    if extra_args:
                        field_annotations[field_name] = extra_args

                    field_offsets[field_name] = (current_offset, field_size)
                    current_offset += field_size
                else:
                    field_size = ctypes.sizeof(annotation)
                    fields.append((field_name, annotation))
                    field_offsets[field_name] = (current_offset, field_size)
                    current_offset += field_size

            # Extract comments from source code
            try:
                import sys
                frame = sys._getframe(1)
                filename = frame.f_code.co_filename
                lineno = frame.f_lineno
                with open(filename, 'r') as f:
                    lines = f.readlines()
                    for i in range(lineno - 1, max(0, lineno - 200), -1):
                        line = lines[i]
                        match = re.match(r'\s*(\w+):\s*[\w\[\]\*,\s]+\s*#\s*(.+)', line)
                        if match:
                            comments[match.group(1)] = match.group(2).strip()
            except:
                pass

            namespace["_fields_"] = fields
            namespace["_field_comments"] = comments
            namespace["_field_annotations"] = field_annotations
            namespace["_field_offsets"] = field_offsets

        return super().__new__(mcs, name, bases, namespace)

class c_struct(ctypes.LittleEndianStructure, metaclass=_CStructMeta):
    """Base class for ctypes structures with annotation support"""
    _pack_ = 1

    @classmethod
    def get_field_at_offset(cls, offset: int) -> Optional[Tuple[str, str, int]]:
        """Find field at given offset within structure."""
        for field_name, (field_offset, field_size) in cls._field_offsets.items():  # type: ignore
            if field_offset <= offset < field_offset + field_size:
                comment = getattr(cls, '_field_comments', {}).get(field_name, "")
                return (field_name, comment, field_size)
        return None

    @classmethod
    def get_field_markers(cls, field_name: str, marker_type: type) -> List[Any]:
        """Get all markers of a specific type for a field."""
        annotations = getattr(cls, '_field_annotations', {}).get(field_name, [])
        return [a for a in annotations if isinstance(a, marker_type)]

    @classmethod
    def get_field_marker(cls, field_name: str, marker_type: type) -> Optional[Any]:
        """Get first marker of a specific type for a field, or None."""
        markers = cls.get_field_markers(field_name, marker_type)
        return markers[0] if markers else None

    @classmethod
    def get_markers_at_offset(cls, offset: int, marker_type: type) -> List[Any]:
        """Get all markers of a specific type at a byte offset."""
        field_info = cls.get_field_at_offset(offset)
        if field_info:
            return cls.get_field_markers(field_info[0], marker_type)
        return []