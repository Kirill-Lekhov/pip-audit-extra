from pip_audit_extra.iface.pip_audit.dataclass import DependencyVuln, Dependency, AuditReport


class TestDependencyVuln:
	def test___init__(self):
		dep_vuln = DependencyVuln(
			id="DEP_VULN_ID",
			aliases=["DEP_VULN_ALIAS_1", "DEP_VULN_ALIAS_2"],
			description="DEP_VULN_DESCRIPTION",
			fix_versions=["DEP_VULN_FIX_VERSION_1", "DEP_VULN_FIX_VERSION_2"],
		)
		assert dep_vuln.id == "DEP_VULN_ID"
		assert dep_vuln.aliases == ["DEP_VULN_ALIAS_1", "DEP_VULN_ALIAS_2"]
		assert dep_vuln.description == "DEP_VULN_DESCRIPTION"
		assert dep_vuln.fix_versions == ["DEP_VULN_FIX_VERSION_1", "DEP_VULN_FIX_VERSION_2"]

	def test_from_dict(self):
		dep_vuln = DependencyVuln.from_dict({
			"id": "DEP_VULN_ID",
			"aliases": ["DEP_VULN_ALIAS_1", "DEP_VULN_ALIAS_2"],
			"description": "DEP_VULN_DESCRIPTION",
			"fix_versions": ["DEP_VULN_FIX_VERSION_1", "DEP_VULN_FIX_VERSION_2"],
		})
		assert dep_vuln.id == "DEP_VULN_ID"
		assert dep_vuln.aliases == ["DEP_VULN_ALIAS_1", "DEP_VULN_ALIAS_2"]
		assert dep_vuln.description == "DEP_VULN_DESCRIPTION"
		assert dep_vuln.fix_versions == ["DEP_VULN_FIX_VERSION_1", "DEP_VULN_FIX_VERSION_2"]


class TestDependency:
	def test___init__(self):
		dep = Dependency(
			name="DEP_NAME",
			version="DEP_VERSION",
			vulns=[
				DependencyVuln(
					id="DEP_VULN_ID",
					aliases=["DEP_VULN_ALIAS_1", "DEP_VULN_ALIAS_2"],
					description="DEP_VULN_DESCRIPTION",
					fix_versions=["DEP_VULN_FIX_VERSION_1", "DEP_VULN_FIX_VERSION_2"],
				),
			],
		)
		assert dep.name == "DEP_NAME"
		assert dep.version == "DEP_VERSION"
		assert len(dep.vulns) == 1
		assert dep.vulns[0].id == "DEP_VULN_ID"
		assert dep.vulns[0].aliases == ["DEP_VULN_ALIAS_1", "DEP_VULN_ALIAS_2"]
		assert dep.vulns[0].description == "DEP_VULN_DESCRIPTION"
		assert dep.vulns[0].fix_versions == ["DEP_VULN_FIX_VERSION_1", "DEP_VULN_FIX_VERSION_2"]

	def test_from_dict(self):
		dep = Dependency.from_dict({
			"name": "DEP_NAME",
			"version": "DEP_VERSION",
			"vulns": [
				{
					"id": "DEP_VULN_ID",
					"aliases": ["DEP_VULN_ALIAS_1", "DEP_VULN_ALIAS_2"],
					"description": "DEP_VULN_DESCRIPTION",
					"fix_versions": ["DEP_VULN_FIX_VERSION_1", "DEP_VULN_FIX_VERSION_2"],
				},
			],
		})
		assert dep.name == "DEP_NAME"
		assert dep.version == "DEP_VERSION"
		assert len(dep.vulns) == 1
		assert dep.vulns[0].id == "DEP_VULN_ID"
		assert dep.vulns[0].aliases == ["DEP_VULN_ALIAS_1", "DEP_VULN_ALIAS_2"]
		assert dep.vulns[0].description == "DEP_VULN_DESCRIPTION"
		assert dep.vulns[0].fix_versions == ["DEP_VULN_FIX_VERSION_1", "DEP_VULN_FIX_VERSION_2"]


class TestAuditReport:
	def test___init__(self):
		report = AuditReport(
			dependencies=[
				Dependency(
					name="DEP_NAME",
					version="DEP_VERSION",
					vulns=[
						DependencyVuln(
							id="DEP_VULN_ID",
							aliases=["DEP_VULN_ALIAS_1", "DEP_VULN_ALIAS_2"],
							description="DEP_VULN_DESCRIPTION",
							fix_versions=["DEP_VULN_FIX_VERSION_1", "DEP_VULN_FIX_VERSION_2"],
						),
					],
				),
			],
		)
		assert len(report.dependencies) == 1
		assert report.dependencies[0].name == "DEP_NAME"
		assert report.dependencies[0].version == "DEP_VERSION"
		assert len(report.dependencies[0].vulns) == 1
		assert report.dependencies[0].vulns[0].id == "DEP_VULN_ID"
		assert report.dependencies[0].vulns[0].aliases == ["DEP_VULN_ALIAS_1", "DEP_VULN_ALIAS_2"]
		assert report.dependencies[0].vulns[0].description == "DEP_VULN_DESCRIPTION"
		assert report.dependencies[0].vulns[0].fix_versions == ["DEP_VULN_FIX_VERSION_1", "DEP_VULN_FIX_VERSION_2"]

	def test__from_dict(self):
		report = AuditReport.from_dict({})
		assert len(report.dependencies) == 0

		report = AuditReport.from_dict({
			"dependencies": [
				{
					"name": "DEP_1_NAME",
					"version": "DEP_1_VERSION",
					"skip_reason": "TEST",
					"vulns": [
						{
							"id": "DEP_1_VULN_ID",
							"aliases": ["DEP_1_VULN_ALIAS_1", "DEP_1_VULN_ALIAS_2"],
							"description": "DEP_1_VULN_DESCRIPTION",
							"fix_versions": ["DEP_1_VULN_FIX_VERSION_1", "DEP_1_VULN_FIX_VERSION_2"],
						},
					],
				},
				{
					"name": "DEP_2_NAME",
					"version": "DEP_2_VERSION",
					"vulns": [
						{
							"id": "DEP_2_VULN_ID",
							"aliases": ["DEP_2_VULN_ALIAS_1", "DEP_2_VULN_ALIAS_2"],
							"description": "DEP_2_VULN_DESCRIPTION",
							"fix_versions": ["DEP_2_VULN_FIX_VERSION_1", "DEP_2_VULN_FIX_VERSION_2"],
						},
					],
				},
			],
		})
		assert len(report.dependencies) == 1
		assert report.dependencies[0].name == "DEP_2_NAME"
		assert report.dependencies[0].version == "DEP_2_VERSION"
		assert len(report.dependencies[0].vulns) == 1
		assert report.dependencies[0].vulns[0].id == "DEP_2_VULN_ID"
		assert report.dependencies[0].vulns[0].aliases == ["DEP_2_VULN_ALIAS_1", "DEP_2_VULN_ALIAS_2"]
		assert report.dependencies[0].vulns[0].description == "DEP_2_VULN_DESCRIPTION"
		assert report.dependencies[0].vulns[0].fix_versions == ["DEP_2_VULN_FIX_VERSION_1", "DEP_2_VULN_FIX_VERSION_2"]
