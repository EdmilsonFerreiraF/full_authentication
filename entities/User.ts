import { Role } from "./Role";

export interface IUser {
    id: string,
    role: Role,
    ownsToken: Function
}