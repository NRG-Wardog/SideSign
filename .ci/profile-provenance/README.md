# Reconstructed source-owned profile/provenance fake gate

This recovery reconstructs reviewed behavior from retained conversation context and surviving exact baseline source objects. These files have new hashes and require a new freeze/review; they do not claim the lost workspace's hashes or runtime results.

No fixture executes native/vendor code, real providers, Apple requests, credentials or personal data. Comparison-only `.invalid` URLs are never requested. Provider/client setup and collector are explicit inert stand-ins. Actual source-owned metadata, data value types, header lock/storage, acquisition/cache/failover/validation bodies, and configuration-selection expressions are compiled into the generated fixture.

```
python3 generate_fixture.py --sources GRAPH --sidesign-root SIGN --anisettekit-root AK --output GENERATED.swift --manifest GENERATED.sources.json
python3 check_sources.py --sources GRAPH --sidesign-root SIGN --anisettekit-root AK --report STATIC.json
swiftc -swift-version 5 -parse-as-library GENERATED.swift -o GENERATED
./GENERATED CASES.json
```

The graph contains SideStore. SideSign defaults to GRAPH/SideSign or GRAPH/SideStore/Dependencies/SideSign; AnisetteKit defaults to GRAPH/AnisetteKit. The generator checks unique top-level declarations and deliberately rejects a duplicate AppConstants mutation before writing output. Shared AppConstants is emitted only once.

Baseline source bytes are hash-bound to SideSign 9757970d656135f0b21dc00700507d099f170320 and SideStore 28dd1f873cad2e12e1c07cacb80ac9685560e02c. The original algorithm runs against the same inert inputs for comparison. No baseline artifact is executed as a script.

Wire contracts:
- hp2: exactly22 tokens, at most512 UTF-8 bytes. Actual GrandSlam client-info and User-Agent selection, generation/provider/cache metadata, public selected verified library hashes, and mapping unobserved. Token21 captures exact requested-versus-returned cache input UTF-8 equality (same/different/unknown), separately from broad family equality. It retains no raw values or hashes and remains unknown without an observed hit. A later caller mutation does not rewrite this historical cache-return fact.
- ap1: exactly12 tokens, at most256 UTF-8 bytes. Latest acquisition event: selected branch/mode, requested profile/blob input, observed selected/clientReady/dataReady/cacheHit boundary, actual observed adapter and selected verification. Loaded mapping and request association remain unobserved. Later event updates use an acquisition token; the real collector epoch/history tests are a separate suite, not this stand-in's claim.

The executable optionally exports exactly12 cases in profile-provenance-cases-v1 with producer actual_hp2_ap1_models_stub_provider_collector. Eight carry actual model hp2/ap1 strings (remote-fresh, changed-config-cache, legacy-negative-cache, verified-public-library, local-custom-library, remote-custom-library, output-mismatch, failover-return); four acquisition failures carry ap1 only (setup, provider, validation, cancel). The separate service/host/copy suite must consume them through both failure routes.

Coverage includes Codable/equality/hash/request-header equality against baseline, 1200 concurrent atomic header snapshot operations,9 config precedence combinations,150 valid model round trips, malformed tokens, cache age boundaries, two different Mac-akd versions in the same broad family, exact byte comparison, legacy decoded metadata, preserved later mutations, actual extracted acquisition/failover choices, and typed cancellation preservation.

Generation and static checks are not Swift execution. The runtime success prefix is PASS hp2_profile_provenance:. Actual collector epoch/history, actual injected HTTP body equivalence, app/Xcode compile, and real authentication remain distinct gates. No fake pass establishes Apple acceptance or loaded native mapping identity.
