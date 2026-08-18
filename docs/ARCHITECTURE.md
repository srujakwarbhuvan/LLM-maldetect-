# System Architecture Diagram

## Component Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        USER INTERFACE LAYER                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  ┌──────────────────┐              ┌──────────────────┐                 │
│  │   CLI Interface  │              │   Python API     │                 │
│  │  (Click + Rich)  │              │   (Direct Use)   │                 │
│  └────────┬─────────┘              └────────┬─────────┘                 │
│           │                                  │                           │
│           └──────────────┬───────────────────┘                           │
└───────────────────────────┼───────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     ORCHESTRATION LAYER                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│                    ┌──────────────────────────┐                          │
│                    │  APKFeatureExtractor     │                          │
│                    │  (Main Pipeline)         │                          │
│                    └────────┬─────────────────┘                          │
│                             │                                             │
│              ┌──────────────┼──────────────┐                             │
│              │              │              │                             │
│              ▼              ▼              ▼                             │
│      ┌─────────────┐ ┌────────────┐ ┌───────────────┐                  │
│      │  Validator  │ │  Logging   │ │  Aggregator   │                  │
│      └─────────────┘ └────────────┘ └───────────────┘                  │
│                                                                           │
└───────────────────────────┬───────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      EXTRACTION LAYER                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │
│  │   Manifest   │  │  Permission  │  │  API Call    │                  │
│  │  Extractor   │  │  Extractor   │  │  Extractor   │                  │
│  │              │  │              │  │              │                  │
│  │ 30+ features │  │ 70+ features │  │100+ features │                  │
│  └──────────────┘  └──────────────┘  └──────────────┘                  │
│                                                                           │
│  ┌──────────────┐  ┌──────────────┐                                     │
│  │ Structural   │  │    Code      │                                     │
│  │  Extractor   │  │  Structure   │                                     │
│  │              │  │  Extractor   │                                     │
│  │ 40+ features │  │ 20+ features │                                     │
│  └──────────────┘  └──────────────┘                                     │
│                                                                           │
│  Each extractor extends BaseExtractor and implements extract() method    │
│                                                                           │
└───────────────────────────┬───────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       DATA MODEL LAYER                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│                    ┌──────────────────────┐                              │
│                    │    APKFeatures       │                              │
│                    │  (Pydantic Model)    │                              │
│                    └──────────┬───────────┘                              │
│                               │                                           │
│            ┌──────────────────┼──────────────────┐                       │
│            │                  │                  │                       │
│            ▼                  ▼                  ▼                       │
│    ┌──────────────┐   ┌─────────────┐   ┌──────────────┐               │
│    │  Manifest    │   │ Permissions │   │   API Calls  │               │
│    │  Features    │   │  Features   │   │   Features   │               │
│    └──────────────┘   └─────────────┘   └──────────────┘               │
│                                                                           │
│    ┌──────────────┐   ┌─────────────┐   ┌──────────────┐               │
│    │   Struct     │   │    Code     │   │  Resources   │               │
│    │  Features    │   │  Features   │   │   Features   │               │
│    └──────────────┘   └─────────────┘   └──────────────┘               │
│                                                                           │
│  • Type validation with Pydantic                                         │
│  • Automatic serialization to dict/JSON                                  │
│  • Flat dictionary conversion for ML                                     │
│                                                                           │
└───────────────────────────┬───────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        OUTPUT LAYER                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│     ┌─────────────┐      ┌─────────────┐      ┌─────────────┐          │
│     │     CSV     │      │    JSON     │      │   Parquet   │          │
│     │  (Pandas)   │      │  (Native)   │      │  (PyArrow)  │          │
│     │             │      │             │      │             │          │
│     │ ML Training │      │ Inspection  │      │  Big Data   │          │
│     └─────────────┘      └─────────────┘      └─────────────┘          │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘


## Data Flow

┌─────────┐
│   APK   │  Input
│  File   │
└────┬────┘
     │
     ▼
┌─────────────────┐
│   Validation    │  Check file integrity, size, format
│   (Pre-check)   │
└────┬────────────┘
     │
     ▼
┌─────────────────┐
│  Androguard     │  Load APK and parse DEX/Manifest
│  APK Object     │
└────┬────────────┘
     │
     ├─────────────────┬─────────────────┬─────────────────┐
     │                 │                 │                 │
     ▼                 ▼                 ▼                 ▼
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ Manifest │    │Permission│    │ API Call │    │Structural│
│Extractor │    │Extractor │    │Extractor │    │Extractor │
└────┬─────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘
     │               │               │               │
     ▼               ▼               ▼               ▼
┌──────────────────────────────────────────────────────────┐
│              Feature Aggregation                         │
│  • Combine all features into APKFeatures model           │
│  • Validate schema                                       │
│  • Handle missing values                                 │
│  • Track errors/warnings                                 │
└────┬─────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────┐
│  Serialization  │  Convert to flat dict
└────┬────────────┘
     │
     ├─────────────┬─────────────┬─────────────┐
     │             │             │             │
     ▼             ▼             ▼             ▼
┌────────┐    ┌────────┐    ┌─────────┐   ┌──────┐
│  CSV   │    │  JSON  │    │ Parquet │   │ Logs │
└────────┘    └────────┘    └─────────┘   └──────┘


## Key Design Patterns

1. **Strategy Pattern**: BaseExtractor with multiple implementations
2. **Facade Pattern**: APKFeatureExtractor as single entry point
3. **Builder Pattern**: Feature aggregation and composition
4. **Validator Pattern**: APKValidator for input validation
5. **Observer Pattern**: Logging throughout pipeline


## Extensibility Points

1. **New Extractors**: Extend BaseExtractor class
2. **Custom Features**: Add fields to Pydantic models
3. **Output Formats**: Extend serialization methods
4. **Validation Rules**: Customize APKValidator
5. **Processing Pipeline**: Modify APKFeatureExtractor workflow


## Quality Assurance Mechanisms

1. **Input Validation**: APKValidator checks file integrity
2. **Type Safety**: Pydantic enforces schema
3. **Error Handling**: Try-catch with logging at each layer
4. **Graceful Degradation**: Continue on non-critical failures
5. **Determinism**: Sorted collections, fixed hashing
6. **Logging**: Multi-level logging (DEBUG/INFO/WARNING/ERROR)
7. **Testing**: Pytest framework with mocks
```

---

**Legend**:
- `┌─┐` = Component boundary
- `│ │` = Vertical connection
- `─` = Horizontal connection
- `▼` = Data flow direction
- `├─┤` = Section separator
