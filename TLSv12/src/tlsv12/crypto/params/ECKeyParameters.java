package tlsv12.crypto.params;

public class ECKeyParameters
{
    ECDomainParameters params;

    protected ECKeyParameters(
        ECDomainParameters  params)
    {

        this.params = params;
    }

    public ECDomainParameters getParameters()
    {
        return params;
    }
}
