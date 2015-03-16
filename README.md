# DbAgnosticMembershipProvider
Implementation of `WebMatrix.WebData.ExtendedMembershipProvider` that only depends on an `IMembershipService`, allowing more than just **Microsoft SQL Server** data access layers.

## User Profile
Define an entity in your data access layer that implements `IUserProfile`.
```c#
public class UserProfile : Pancake.MembershipProviders.IUserProfile
{
  public virtual int Id { get; set; }
  public virtual string Username { get; set; }
  
  // Other properties...
}
```

## Membership Service
Define a service in your data or service layer that implements `IMembershipService`. **NHibernate** is used in the below example to connect to an **Oracle 10g** database.
```c#
public class MembershipService : Pancake.MembershipProviders.IMembershipService<IUserProfile>
{
  private readonly static ISessionFactory SessionFactory;
  private readonly ISession _session;

  static MembershipService()
  {
    var configure = new NHibernate.Cfg.Configuration()
      .DataBaseIntegration(x =>
      {
        x.Driver<OracleClientDriver>();
        x.Dialect<Oracle10gDialect>();
        x.ConnectionString = ConfigurationManager.ConnectionStrings["MyConnectionString"];
      }
      .CurrentSessionContext<WebSessionContext>();
      
    var mapper = new ModelMapper();
    mapper.AddMappings(Assembly.GetExecutingAssembly().GetExportedTypes());
    var domainMapping = mapper.CompileMappingForAllExplicitlyAddedEntities();
    configure.AddMapping(domainMapping);
    configure.BuildMappings();
      
    SessionFactory = configure.BuildSessionFactory();
  }
  
  public MembershipService()
  {
    _session = SessionFactory.OpenSession();
  }
  
  // Implement interface methods here
  
  public IUserProfile GetUserById(int id)
  {
      return _session.Get<UserProfile>(id);
  }

  public IUserProfile GetUserByName(string username)
  {
    return _session.Query<UserProfile>()
      .SingleOrDefault(x => x.Username.ToUpperInvariant() == username.ToUpperInvariant());
  }
  
  // etc...
}
```

## Web.config
Add a provider under the `<providers>` element in your configuration.
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
