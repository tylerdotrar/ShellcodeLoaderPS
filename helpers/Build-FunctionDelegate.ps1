function Build-FunctionDelegate ($ParameterTypes, $ReturnType ) {
    $DynAssembly     = [System.Reflection.AssemblyName]::new([guid]::NewGuid().ToString())
    $AssemblyBuilder = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder   = $AssemblyBuilder.DefineDynamicModule([guid]::NewGuid().ToString())

    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, @([Object], [IntPtr])) 
    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')

    # Specify target function parameter types and return type
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $ParameterTypes)
    $MethodBuilder.SetImplementationFlags('Runtime, Managed')

    return $TypeBuilder.CreateType()
}