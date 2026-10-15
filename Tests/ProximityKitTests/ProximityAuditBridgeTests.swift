// ProximityAuditBridgeTests.swift
// ProximityKitTests
//
// ProximityKit plan step A0.2, the audit sink: ProximityKit writes every audit line through
// `ProximityAudit.log(_:context:)` to the sink its host installs, and drops the line while none is
// installed. The source walls that count or forbid audit lines read that one spelling (the routed
// refusal budget counts `ProximityAudit.log(` in the digest doors, the retry planner forbids
// `ProximityAudit`), so ProximityKit code must name the Fernlet repository's own log, `FernletAuditLog`,
// nowhere: a line written straight to it would bypass the sink and hide from them.
//
// A partial copy (ProximityKit plan step A1.3, which copies into the package every cell of the Fernlet
// repository's tests that reads this module's sources before that repository stops holding them): of
// the Fernlet repository's FernletTests file of the same name, this holds only
// `ProximityAuditBridgeTests.proximityKitCodeNamesFernletAuditLogNowhere`, with the suite's name and
// its own unchanged, the module walked through the package's walker
// (`TestSupport/PackageSwiftFiles.swift`) at its floor. The bridge's canary cells and the install-site
// wall over Fernlet's trees stay in that repository's original; this package's own install-site wall is
// `PackageTestTreeWallTests.onlyThePackageTestsInstallerInstallsAnAuditSink`.

import Foundation
import Testing

/// ProximityKit has no way to audit but its host's sink: no code line of the module names the Fernlet
/// repository's `FernletAuditLog`, and the module still audits through `ProximityAudit.log(`.
@Suite struct ProximityAuditBridgeTests {

    /// ProximityKit code names `FernletAuditLog` nowhere: every audit line in the module goes
    /// through the host's sink, spelled `ProximityAudit.log(`.
    ///
    /// The source walls that count or forbid audit lines read that one spelling, so a line written
    /// straight to `FernletAuditLog` would bypass the sink AND hide from them. Comments may still
    /// name it (doc comments explain its redaction and its process-global registry); the scan
    /// reads code lines only. In the package the Fernlet module cannot be imported at all
    /// (ProximityKit depends on nothing), so what this holds here is that no code line spells the name,
    /// a local type or alias of it included. The walk is the package's walker, held to its floor, where
    /// the original held its own walk to 50 files.
    @Test func proximityKitCodeNamesFernletAuditLogNowhere() throws {
        let files = try PackageSwiftFiles.sources()
        var sinkCalls = 0
        var offenders: [String] = []
        // R2: bounded by the module's own file list.
        for file in files {
            let code = MeshRoutedSourceScan.codeOnly(file.text)
            sinkCalls += code.components(separatedBy: "ProximityAudit.log(").count - 1
            if code.contains("FernletAuditLog") {
                offenders.append(file.path)
            }
        }
        #expect(files.count >= PackageSwiftFiles.sourceFloor, """
            the ProximityKit sweep read only \(files.count) Swift files (floor \(PackageSwiftFiles.sourceFloor))
            """)
        #expect(sinkCalls > 0, "the sweep found no `ProximityAudit.log(` call: wrong tree?")
        #expect(offenders.isEmpty, """
            ProximityKit code names FernletAuditLog in \(offenders). Audit through \
            `ProximityAudit.log(_:context:)`, which reaches Fernlet's log through the installed \
            bridge and every other host's sink too.
            """)
    }
}
