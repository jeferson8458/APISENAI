/*
  Warnings:

  - Added the required column `password_hash` to the `Users` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE `users` ADD COLUMN `password_hash` VARCHAR(191) NOT NULL;
