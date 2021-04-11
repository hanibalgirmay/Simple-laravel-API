<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Response;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $r)
    {
        $body_fields = $r->validate([
            'name' => 'required | string',
            'email' => 'required |string|unique:users,email',
            'password' => 'required | string| confirmed'
        ]);

        $user = User::create([
            'name' => $body_fields['name'],
            'email' => $body_fields['email'],
            'password' => bcrypt($body_fields['password'])
        ]);

        $token = $user->createToken('myappToken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token,
        ];

        return response($response, 201);
    }

    public function login(Request $r)
    {
        $body_fields = $r->validate([
            'email' => 'required |string',
            'password' => 'required | string'
        ]);

        //check if email exist
        $user = User::where('email', $body_fields['email'])->first();

        //check pass
        if (!$user || !Hash::check($body_fields['password'], $user->password)) {
            return response([
                "message" => 'Bad credentials'
            ], 401);
        }

        $token = $user->createToken('myappToken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token,
        ];

        return response($response, 201);
    }

    public function logout(Request $r)
    {
        auth()->user()->tokens()->delete();
        return [
            'message' => 'logged out'
        ];
    }
}
