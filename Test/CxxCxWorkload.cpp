int CxxCxWorkload()
{
    // Construct a Windows Runtime reference exception in the native C++/CX runtime.
    auto value = ref new Platform::FailureException("Detourist");
    auto message = value->Message;
    auto text = value->ToString();
    return value && message && text ? 0 : 1;
}
