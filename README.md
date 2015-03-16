# DbAgnosticMembershipProvider
Implementation of **WebMatrix.WebData.ExtendedMembershipProvider** that only depends on an **IMembershipService**, allowing more than just MS SQL Server data access layers.


## Web.config

```xml
<configuration>
  <!-- snip -->
  <system.web>
    <!-- snip -->
    <membership defaultProvider="DbAgnosticMembershipProvider">
      <providers>
        <clear />
        <add name="DbAgnosticMembershipProvider" 
             type="Pancake.MembershipProviders.DbAgnosticMembershipProvider"
             enablePasswordRetrieval="true"
             enablePasswordReset="true"
             requireQuestionAndAnswer="false" />
      </providers>
    </membership>
    <!-- snip -->
  </system.web>
  <!-- snip -->
</configuration>
```
