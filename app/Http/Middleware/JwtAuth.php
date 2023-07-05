<?php

namespace App\Http\Middleware;

use Closure;
use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;

class jwtAuth
{
  /**
   * Handle an incoming request.
   *
   * @param  \Illuminate\Http\Request  $request
   * @param  \Closure  $next
   * @return mixed
   */
  public function handle(Request $request, Closure $next)
  {
    $token = $request->header('access_token');
    $key = env('JWT_SECRET');
    if (!$token) return response()->json(['message' => 'unauthorized'], 401);

    try {
      $checkToken = JWT::decode($token, new Key($key, "HS256"));
    } catch (Exception $e) {
      return response()->json(['message' => 'unauthorized'], 401);
    }


    $request->request->add(['user' => $checkToken]);
    return $next($request);
  }
}
