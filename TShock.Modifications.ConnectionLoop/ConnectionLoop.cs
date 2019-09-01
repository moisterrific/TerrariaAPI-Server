using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Mono.Cecil;
using Mono.Cecil.Cil;
using OTAPI.Patcher.Engine;
using OTAPI.Patcher.Engine.Extensions.ILProcessor;
using OTAPI.Patcher.Engine.Modification;
using Terraria;

namespace TShock.Modifications.ConnectionLoop
{
	/// <summary>
	///     This modification is used to inject a network check which ensures that the sever does not enter an infinite loop
	///     when clients repeatedly connect and disconnect.
	/// </summary>
	public sealed class ConnectionLoop : ModificationBase
	{
		/// <inheritdoc />
		public override IEnumerable<string> AssemblyTargets =>
			new[] {"OTAPI, Version=1.3.0.7, Culture=neutral, PublicKeyToken=null"};

		/// <inheritdoc />
		public override string Description => "Patching connection loop exploit...";

		/// <inheritdoc />
		public override void Run()
		{
			var checkBytes = Method(() => Terraria.NetMessage.CheckBytesDirect(0));

			// Find the proper instruction range => if (i < num2)
			var targetInstruction = checkBytes.Body.Instructions.Single(i =>
				i.OpCode == OpCodes.Blt_S && i.Previous.OpCode == OpCodes.Ldloc_3 &&
				i.Previous.Previous.OpCode == OpCodes.Ldloc_2);

			checkBytes.Body.GetILProcessor().InsertAfter(targetInstruction,
				new[]
				{
					Instruction.Create(OpCodes.Ldloc_3),
					Instruction.Create(OpCodes.Brfalse_S, targetInstruction.Operand as Instruction),
				}.AsEnumerable());

			// After inserted 2 short form instructions are out of bound.
			foreach (var i in checkBytes.Body.Instructions)
			{
				if (i.OpCode == OpCodes.Blt_S || i.OpCode == OpCodes.Br_S)
				{
					if(Math.Abs((i.Operand as Instruction).Offset - i.Offset) >= 120)
					{
						i.OpCode = i.OpCode == OpCodes.Blt_S ? OpCodes.Blt : OpCodes.Br;
					}
				}
			}
		}
	}
}
