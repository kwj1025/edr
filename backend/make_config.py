# make_config.py
config = """<Sysmon schemaversion="4.90">
  <EventFiltering>

    <!-- ID 1: 모든 프로세스 생성 수집 -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Rule groupRelation="or">
          <Image condition="contains">exe</Image>
        </Rule>
      </ProcessCreate>
    </RuleGroup>

    <!-- ID 3: 모든 네트워크 연결 수집 -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <Rule groupRelation="or">
          <Image condition="contains">exe</Image>
        </Rule>
      </NetworkConnect>
    </RuleGroup>

    <!-- ID 5: 모든 프로세스 종료 수집 -->
    <RuleGroup name="" groupRelation="or">
      <ProcessTerminate onmatch="include">
        <Rule groupRelation="or">
          <Image condition="contains">exe</Image>
        </Rule>
      </ProcessTerminate>
    </RuleGroup>

    <!-- ID 22: 모든 DNS 쿼리 수집 -->
    <RuleGroup name="" groupRelation="or">
      <DnsQuery onmatch="include">
        <Rule groupRelation="or">
          <Image condition="contains">exe</Image>
        </Rule>
      </DnsQuery>
    </RuleGroup>

  </EventFiltering>
</Sysmon>"""

with open("sysmon_config.xml", "w", encoding="utf-8") as f:
    f.write(config)

print("sysmon_config.xml 생성 완료")